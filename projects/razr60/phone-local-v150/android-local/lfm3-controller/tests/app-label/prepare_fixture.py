"""Extract actual controller prompt/answer and engine receipt code with explicit IO fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path

def prepare(source, output):
    source, output = Path(source), Path(output)
    helper = source / "tests/exact-admission/prepare_fixture.py"
    spec = importlib.util.spec_from_file_location("app_label_admission_fixture", helper)
    base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
    files, record = base.prepare(source, output)
    package = source / "src/org/trillionnium/hepta/local"
    controller = (package / "LocalTaskController.java").read_text()
    engine = (package / "LocalModelEngine.java").read_text()
    answer = base.section(controller, "    private static String answerJson(", "    private static String chineseAction(")
    receipt = base.section(engine, '                put(receipt,"grammar_schema",', '            File resultFile = ')
    if not receipt.endswith("            }\n"):
        raise RuntimeError("receipt block closing anchor differs")
    receipt = receipt[:-len("            }\n")]
    for call in ("ActionDecision.parse(answer.text,frame.grammar.schema)",
                 "ActionPolicy.validateAuthorizedDecision(action,before.packageName,frame.appPackages,frame.targets,frame.grammar.appLabels,authorization,frame.grammar.authorization)",
                 "DecisionGrammar.createAuthorized(observation.id,observation.packageName,packages,clicks,edits,scrolls,targets,appLabels,authorization)"):
        if controller.count(call) != 1:
            raise RuntimeError("exact candidate production call site missing or ambiguous: " + call)
    fixture = output / "PromptAdmissionFixture.java"
    text = fixture.read_text()
    old = "        public final ConservativeTokenBudget budget;"
    if text.count(old) != 1: raise RuntimeError("fixture budget anchor not unique")
    text = text.replace(old, old + "\n        public final DecisionGrammar grammar;")
    old = "            text=frame.text;budget=frame.budget;ids=frame.nodeIds;"
    if text.count(old) != 1: raise RuntimeError("fixture result anchor not unique")
    text = text.replace(old, old + "grammar=frame.grammar;")
    if not text.endswith("}\n"): raise RuntimeError("fixture class closing anchor differs")
    methods = "\n" + answer + """
    public static String serialize(ActionDecision action)throws Exception{return answerJson(action);}
    public static JSONObject grammarReceipt(DecisionGrammar grammarObject)throws Exception{
        JSONObject receipt=new JSONObject();
        java.io.File grammar=new java.io.File("synthetic-grammar.gbnf");
""" + receipt.replace("r.controllerGrammar", "grammarObject") + """
        return receipt;
    }
    private static void put(JSONObject object,String key,Object value)throws Exception{object.put(key,value);}
"""
    fixture.write_text(text[:-2] + methods + "}\n")
    record["scope"] += "; exact production answerJson and engine grammar receipt field construction; pure parser/policy/grammar are compiled unchanged"
    record["extracted_parts"]["answer_json"] = {"bytes": len(answer.encode()), "sha256": hashlib.sha256(answer.encode()).hexdigest()}
    record["extracted_parts"]["grammar_receipt"] = {"bytes": len(receipt.encode()), "sha256": hashlib.sha256(receipt.encode()).hexdigest()}
    record["receipt_fixture_only_identifier_substitution"] = "r.controllerGrammar -> grammarObject; File and JSON put are explicit IO fixtures"
    record["production_controller_v4_call_sites_checked"] = True
    record["full_android_controller_thread_executed"] = False
    (output / "EXTRACTION.json").write_text(json.dumps(record, indent=2) + "\n")
    return files, record
