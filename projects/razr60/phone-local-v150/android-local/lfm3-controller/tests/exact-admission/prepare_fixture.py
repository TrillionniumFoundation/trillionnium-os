"""Compile exact production prompt/admission/input-limit decisions with explicit IO fixtures."""
import ast
import hashlib
import json
from pathlib import Path
import re


def section(text, start, end):
    if text.count(start) != 1 or text.count(end) != 1:
        raise RuntimeError("production admission anchors are not unique")
    first = text.index(start)
    return text[first:text.index(end, first)]


def prepare(source, output):
    source, output = Path(source), Path(output)
    output.mkdir(parents=True, exist_ok=True)
    package = source / "src/org/trillionnium/hepta/local"
    controller = (package / "LocalTaskController.java").read_text(encoding="utf-8")
    engine = (package / "LocalModelEngine.java").read_text(encoding="utf-8")
    service = (package / "HeptaAccessibilityService.java").read_text(encoding="utf-8")
    await_block = section(controller, "    private ModelAnswer awaitModel(", "        long remaining=taskDeadline-SystemClock.elapsedRealtime();")
    await_guard = await_block[await_block.index("{") + 1:]
    limited = section(service, "    static String limited(", "    static String message(")
    parts = {
        "system": section(controller, "    private static final String SYSTEM=", "    public LocalTaskController("),
        "prompt_builder": section(controller, "    private static final class PromptFrame {",
                                  "    private static JSONObject catalogueJson("),
        "completion_observation_bridge": section(controller, "    private static NotesCompletionEvidence.Frame completionFrame(", "    private static NotesCreateWorkflow.Observation workflowObservation("),
        "await_guard": await_guard,
        "text_limit": section(engine, "    private static void validateText(", "    private static void privateDirectory("),
        "label_limit": limited,
    }
    postparse = section(controller, "                        action=ActionDecision.parse(answer.text,frame.grammar.schema);",
                        '                        if("submit".equals(action.action)')
    before_dispatch = section(controller, "                if(repeatGuard.rejects(action,before.state)",
                              '                emit("正在执行第 "+steps+')
    if postparse.count("frame.requireTextOnlyClick(action);") != 1 or before_dispatch.count("frame.requireTextOnlyClick(action);") != 1:
        raise RuntimeError("actual postparse and pre-dispatch click guards must both use the frozen frame domain")
    parts["postparse_click_guard"] = postparse
    parts["predispatch_click_guard"] = before_dispatch
    text_limit = re.findall(r"private static final int TEXT_LIMIT\s*=\s*(\d+);", engine)
    if len(text_limit) != 1:
        raise RuntimeError("one production text byte limit required")
    fixture = """package org.trillionnium.hepta.local;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.json.JSONArray;
import org.json.JSONObject;
public final class PromptAdmissionFixture {
""" + parts["system"] + parts["completion_observation_bridge"] + parts["prompt_builder"] + """
    public static final class Result {
        public final String text;
        public final DecisionGrammar grammar;
        public final ConservativeTokenBudget budget;
        public final java.util.Set<String> ids;
        public final java.util.Set<String> clickIds;
        private final PromptFrame frame;
        public final int nodes,required,visibleText,history;
        public final RecentActionProjection.ReadableEvents events;
        public final JSONObject budgetReceipt;
        Result(PromptFrame frame)throws Exception{
            this.frame=frame;clickIds=frame.clickNodeIds;
            text=frame.text;grammar=frame.grammar;budget=frame.budget;ids=frame.nodeIds;
            nodes=frame.nodesShown;required=frame.requiredNodes;
            visibleText=frame.visibleTextShown;history=frame.historyShown;
            events=frame.eventHistory;budgetReceipt=frame.budgetJson();
        }
        public void requireTextOnlyClick(ActionDecision action)throws ActionDecision.InvalidActionException{
            frame.requireTextOnlyClick(action);
        }
    }
    public static Result build(String owner,AppCatalogueRanker.Page apps,PhoneObservation observation,
            JSONArray history,LocalRuntimeConfig config)throws Exception{
        return buildWithDecision(owner,apps,observation,history,config,null);
    }
    public static Result buildWithDecision(String owner,AppCatalogueRanker.Page apps,PhoneObservation observation,
            JSONArray history,LocalRuntimeConfig config,LastModelDecisionProjection prior)throws Exception{
        return new Result(prompt(owner,apps,observation,history,null,prior,null,config,
                new RepeatActionGuard(),new SameStateNoEffectGuard(),TaskAuthorization.parse(owner).bind("cccccccccccccccccccccccccccccccc").frame(),null));
    }
    private interface InferenceConfig { LocalRuntimeConfig configuration(); }
    public static void awaitAdmission(String prompt,final LocalRuntimeConfig config)throws Exception{
        InferenceConfig inference=new InferenceConfig(){
            public LocalRuntimeConfig configuration(){return config;}
        };
""" + parts["await_guard"] + """
    }
    public static void inputText(String text,boolean required)throws IOException {validateText(text,required);}
    public static String system(){return SYSTEM;}
    private static final int TEXT_LIMIT=""" + text_limit[0] + ";\n" + parts["text_limit"] + "\n}\n"
    helper = "package org.trillionnium.hepta.local;\nfinal class HeptaAccessibilityService {\n" + limited + "}\n"
    files = []
    for name, value in (("PromptAdmissionFixture.java", fixture), ("HeptaAccessibilityService.java", helper)):
        path = output / name
        path.write_text(value, encoding="utf-8")
        files.append(path)
    tree = ast.parse((source / "tools/run_host_checks.py").read_text(encoding="utf-8"))
    values = [ast.literal_eval(item.value) for item in tree.body if isinstance(item, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == "PURE_CLASSES" for target in item.targets)]
    if len(values) != 1:
        raise RuntimeError("one production pure-class list required")
    files += [package / (name + ".java") for name in values[0]] + [package / "PhoneObservation.java"]
    web_fixture_source=source/"tests/web-flight/legacy-boundary/WebFlightDomain.java"
    web_fixture_raw=web_fixture_source.read_bytes()
    web_fixture_compile=output/"WebTaskDomain.java"
    web_fixture_compile.write_bytes(web_fixture_raw)
    if web_fixture_compile.read_bytes()!=web_fixture_raw or web_fixture_source.read_bytes()!=web_fixture_raw:
        raise RuntimeError("Exact Web type-boundary compiler copy required")
    files += [package / "web/WebFlightGoal.java",package / "web/WebShoppingGoal.java",web_fixture_compile,
              source/"tests/web-flight/legacy-boundary/WebShoppingQuote.java"]
    files += [source/"src/org/trillionnium/hepta/background"/(name+".java") for name in ("FixedIntentTools","FixedIntentTarget","BrokerProtocol")]
    digest = lambda value: hashlib.sha256(value).hexdigest()
    record = {
        "scope": "Exact production full prompt builder, Java pre-native guard and LocalModelEngine UTF-8 input limit; Android Rect and JSON serialization are explicit IO fixtures",
        "controller_sha256": digest(controller.encode()),
        "engine_sha256": digest(engine.encode()),
        "budget_sha256": digest((package / "ConservativeTokenBudget.java").read_bytes()),
        "extracted_parts": {name: {"bytes": len(value.encode()), "sha256": digest(value.encode())}
                            for name, value in parts.items()},
        "text_byte_limit": int(text_limit[0]),
        "web_fixture_boundary": "Type-only WebTaskDomain; every Web capability method throws",
        "web_fixture_compiler_copy": {"source_path":str(web_fixture_source.relative_to(source)),
            "compiler_path":str(web_fixture_compile),"bytes":len(web_fixture_raw),
            "sha256":hashlib.sha256(web_fixture_raw).hexdigest(),"byte_identical":True},
        "not_android_runtime": True,
        "not_model_inference": True,
        "not_phone_test": True,
        "observation_scope": "explicit host boundary observations and hash-pinned saved phone failure observations; no live phone run",
    }
    (output / "EXTRACTION.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return files, record
