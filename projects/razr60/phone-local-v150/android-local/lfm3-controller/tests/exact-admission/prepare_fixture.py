"""Compile exact production prompt/admission/input-limit decisions with explicit IO fixtures."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import re


def legacy_session_parent_proof(raw):
    """Proof copy only; actual compilation retains the current refusing type port."""
    parent_sha="3fff6e7e892adca8a9e895a852447f55237124e6545c1fb3aa2c9b047a0e3ddd"
    current_sha="8ee6f4d05dc3f71ed646215947e10c9d34b12b4354ed6920ca49b06112dd5203"
    digest=hashlib.sha256(raw).hexdigest()
    if digest==parent_sha:return raw
    if digest!=current_sha:raise RuntimeError("unknown legacy Session type-port source")
    added=(b"        // Type-only final-use projection; this guard still cannot be constructed.\n"
           b"        final NativeAppEvidence.Frame frame=null;\n")
    if raw.count(added)!=1:raise RuntimeError("unique exact Frame type-port addition required")
    proof=raw.replace(added,b"",1)
    if hashlib.sha256(proof).hexdigest()!=parent_sha:
        raise RuntimeError("complete original refusing Session proof differs")
    return proof


def section(text, start, end):
    if text.count(start) != 1 or text.count(end) != 1:
        raise RuntimeError("production admission anchors are not unique")
    first = text.index(start)
    return text[first:text.index(end, first)]



def calendar_legacy_types(source, output, files):
    """Private, rejecting compiler shapes for this original non-calendar gate."""
    old=source/"tests/native-app/legacy-boundary/NativeAppSession.java"
    raw=old.read_bytes()
    if files.count(old)!=1 or hashlib.sha256(legacy_session_parent_proof(raw)).hexdigest()!="3fff6e7e892adca8a9e895a852447f55237124e6545c1fb3aa2c9b047a0e3ddd":
        raise RuntimeError("Exact original refusing Session compiler input required")
    inserted=b"""
    static final class CalendarOffer {
        final NativeCalendarDateEnvelope source=null;
        final CalendarGrammar protocol=null;
        private CalendarOffer(){throw unavailable();}
        void claimGrammar(TaskAuthorization.Frame owner)throws Exception{throw unavailable();}
        void close(){throw unavailable();}
    }
    static final class CalendarGrammar {
        final String grammar=null,grammarSha256=null;
        private CalendarGrammar(){throw unavailable();}
    }
"""
    end=raw.rfind(b"\n}")
    if end<0 or raw[end:].strip()!=b"}" or b"class CalendarOffer" in raw:
        raise RuntimeError("Exact original Session class boundary required")
    compiled=raw[:end]+inserted+raw[end:]
    if compiled.replace(inserted,b"",1)!=raw:raise RuntimeError("Session compiler copy is not reversible")
    constant_source=source/"src/org/trillionnium/hepta/local/NativeCalendarDateIntent.java"
    constant_raw=constant_source.read_bytes()
    constants=b'    static final String SCHEMA="hepta.native-calendar-select-date.v1",ACTION="calendar.select_date";'
    if constant_raw.splitlines().count(constants)!=1:raise RuntimeError("Actual calendar schema/action constants changed")
    ports=output/"calendar-legacy-types";ports.mkdir()
    values=[
      ("NativeAppSession.java",compiled),
      ("NativeCalendarDateEnvelope.java",b"""package org.trillionnium.hepta.local;
final class NativeCalendarDateEnvelope {
    final NativeAppEvidence.Frame facts=null;
    private NativeCalendarDateEnvelope(){throw new UnsupportedOperationException("No calendar envelope in original prompt gate");}
}
"""),
      ("NativeCalendarDateIntent.java",b"""package org.trillionnium.hepta.local;
final class NativeCalendarDateIntent {
"""+constants+b"""
    private NativeCalendarDateIntent(){throw new UnsupportedOperationException("No calendar intent in original prompt gate");}
}
""")]
    generated=[]
    for name,value in values:
        p=ports/name
        with p.open("xb") as stream:stream.write(value)
        generated.append(p)
    if any(Path(p).name in ("NativeCalendarDateEnvelope.java","NativeCalendarDateIntent.java") for p in files):
        raise RuntimeError("Calendar compiler shape would duplicate an existing source")
    files=[generated[0] if p==old else p for p in files]+generated[1:]
    def meta(p):
        value=p.read_bytes()
        return {"path":str(p),"bytes":len(value),"sha256":hashlib.sha256(value).hexdigest()}
    return files,{"original_session":meta(old),"constant_source":meta(constant_source),
      "generated":[meta(p) for p in generated],"original_session_inverse_equal":True,
      "private_constructors_and_all_calendar_methods_throw":True,
      "calendar_authority_created":False,"calendar_behavior_executed":False}

def prepare(source, output):
    source, output = Path(source), Path(output)
    output.mkdir(parents=True, exist_ok=True)
    package = source / "src/org/trillionnium/hepta/local"
    controller = (package / "LocalTaskController.java").read_text(encoding="utf-8")
    engine = (package / "LocalModelEngine.java").read_text(encoding="utf-8")
    service = (package / "HeptaAccessibilityService.java").read_text(encoding="utf-8")
    await_start="    private ModelAnswer awaitModel("
    if controller.count(await_start)!=1:raise RuntimeError("one actual model admission method required")
    # Earlier calendar code has its own remaining budget; retain this exact method.
    await_block = section(controller[controller.index(await_start):], await_start, "        long remaining=taskDeadline-SystemClock.elapsedRealtime();")
    await_guard = await_block[await_block.index("{") + 1:]
    # This original fixture accepts only prompt/config, never a typed Offer or
    # grammar. Project only the explicit search branches and keep the ordinary,
    # visual, and form-history guard bytes, including runtime configuration.
    full_await_guard=await_guard
    search_start='        final boolean searchProtocol=grammar!=null&&NativeSearchDecision.SCHEMA.equals(grammar.schema);'
    system_selection='        final String system=searchProtocol?NATIVE_SEARCH_SYSTEM:systemPrompt(runtime,nativeApp);'
    native_search_selection="            if(searchProtocol){\n                NativeSearchSession search=activeNativeSearch;\n                if(search==null||search.nativeTask!=nativeTask||search.background!=background||taskDeadline!=search.chainDeadlineElapsed)\n                    throw new IllegalStateException(\"搜索模型必须使用同一实际 Session 和首次固定的链期限\");\n                search.requireModelPlanning(grammar,SystemClock.elapsedRealtime());\n            }else nativeTask.requireModelPlanning();\n"
    legacy_native_selection='            nativeTask.requireModelPlanning();\n'
    search_only=section(await_guard,'\n        if(searchProtocol){\n','\n'+system_selection)[1:]+'\n'
    legacy_system_selection='        final String system=systemPrompt(runtime,nativeApp);'
    projections=((search_start+'\n',''),(native_search_selection,legacy_native_selection),
                 (search_only,''),(system_selection,legacy_system_selection))
    for actual,legacy in projections:
        if await_guard.count(actual)!=1:
            raise RuntimeError("one complete actual search-only admission region required")
        await_guard=await_guard.replace(actual,legacy,1)
    restored=await_guard.replace(legacy_system_selection,search_only+system_selection,1)
    restored=restored.replace(legacy_native_selection,native_search_selection,1)
    restored=restored.replace('        if(nativeApp){',search_start+'\n        if(nativeApp){',1)
    if restored!=full_await_guard:
        raise RuntimeError("ordinary admission projection changed bytes outside the search branches")
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
        public final JSONObject budgetReceipt,visualPromptEvidence;
        Result(PromptFrame frame)throws Exception{
            this.frame=frame;clickIds=frame.clickNodeIds;
            text=frame.text;grammar=frame.grammar;budget=frame.budget;ids=frame.nodeIds;
            nodes=frame.nodesShown;required=frame.requiredNodes;
            visibleText=frame.visibleTextShown;history=frame.historyShown;
            events=frame.eventHistory;budgetReceipt=frame.budgetJson();
            visualPromptEvidence=frame.visualPromptOriginal==null?null:frame.visualPromptEvidence();
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
    private interface InferenceConfig { LocalRuntimeConfig configuration(); boolean acceptsObservedImage(); }
    public static void awaitAdmission(String prompt,final LocalRuntimeConfig config)throws Exception{
        final NativeAppSession activeNativeTask=null; // Type-only native boundary; every operation throws.
        final boolean nativeApp=false; // This original fixture exercises ordinary/visual admission.
        final PhoneObservation before=null; // No historical native observation can enter this original fixture.
        InferenceConfig inference=new InferenceConfig(){
            public LocalRuntimeConfig configuration(){return config;}
            public boolean acceptsObservedImage(){throw new AssertionError("native form-history image admission is outside this ordinary fixture");}
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
    files += [package / (name + ".java") for name in values[0]] + [package / "PhoneObservation.java", package / "VisualPromptProjection.java"]
    files += [source / "tests/native-app/legacy-boundary/NativeAppSession.java"]
    files += [source / "tests/native-app/legacy-boundary/NativeSearchSession.java",
              source / "tests/native-app/legacy-boundary/NativeSearchPlanning.java"]
    web_fixture_source=source/"tests/web-flight/legacy-boundary/WebFlightDomain.java"
    web_fixture_raw=web_fixture_source.read_bytes()
    web_fixture_compile=output/"WebTaskDomain.java"
    web_fixture_compile.write_bytes(web_fixture_raw)
    if web_fixture_compile.read_bytes()!=web_fixture_raw or web_fixture_source.read_bytes()!=web_fixture_raw:
        raise RuntimeError("Exact Web type-boundary compiler copy required")
    files += [package / "web/WebFlightGoal.java",package / "web/WebShoppingGoal.java",web_fixture_compile,
              source/"tests/web-flight/legacy-boundary/WebShoppingQuote.java"]
    files += [source/"src/org/trillionnium/hepta/background"/(name+".java") for name in ("FixedIntentTools","FixedIntentTarget","BrokerProtocol","PublicPermissionControllerUi","PublicOwnGroupPolicy","ProfileIdentity","ProfileTarget","WindowOwnership")]
    # PURE_CLASSES is only the actual pure Java list. Reuse the exact old-domain
    # boundary which canonical adds separately; no automatic selection exists here.
    auto_helper=source/"tests/native-app/legacy-boundary/prepare_search_pure.py"
    auto_raw=auto_helper.read_bytes()
    if hashlib.sha256(auto_raw).hexdigest()!="ffc48511fe5bee96cc27853570ab7cde1ddf54f9162de50991afff2501888889":
        raise RuntimeError("Exact reviewed old-domain automatic compiler helper required")
    spec=importlib.util.spec_from_file_location("exact_admission_auto_boundary",auto_helper)
    auto_boundary=importlib.util.module_from_spec(spec);spec.loader.exec_module(auto_boundary)
    files=auto_boundary.add_auto_boundary(source,files)
    auto_port=source/"tests/native-app/legacy-boundary/BackgroundAutoTargetResolver.java"
    files,calendar_copy=calendar_legacy_types(source,output,files)
    digest = lambda value: hashlib.sha256(value).hexdigest()
    record = {
        "calendar_fixture_compiler_copy": calendar_copy,
        "automatic_fixture_compiler_boundary": {
            "helper":{"path":str(auto_helper),"bytes":len(auto_raw),"sha256":digest(auto_raw)},
            "source":{"path":str(auto_port),"bytes":auto_port.stat().st_size,"sha256":digest(auto_port.read_bytes())},
            "complete_actual_background_target_retained":True,
            "private_constructors_and_all_operations_throw":True,
            "actual_automatic_resolver_compiled":False,"automatic_authority_created":False},
        "scope": "Exact production full prompt builder, original ordinary/visual pre-native guard projection and LocalModelEngine UTF-8 input limit; Android Rect and JSON serialization are explicit IO fixtures",
        "controller_sha256": digest(controller.encode()),
        "engine_sha256": digest(engine.encode()),
        "budget_sha256": digest((package / "ConservativeTokenBudget.java").read_bytes()),
        "extracted_parts": {name: {"bytes": len(value.encode()), "sha256": digest(value.encode())}
                            for name, value in parts.items()},
        "text_byte_limit": int(text_limit[0]),
        "native_search_admission_excluded_from_original_fixture": {
            "full_current_await_guard_sha256": digest(full_await_guard.encode()),
            "excluded_search_branch_bytes": len(search_only.encode()),
            "excluded_search_branch_sha256": digest(search_only.encode()),
            "excluded_search_protocol_declaration_sha256": digest((search_start+"\n").encode()),
            "excluded_native_search_selection_sha256": digest(native_search_selection.encode()),
            "ordinary_runtime_configuration_retained_verbatim": True,
            "actual_system_selection_sha256": digest(system_selection.encode()),
            "ordinary_system_prompt_expression": "systemPrompt(runtime,nativeApp)",
            "projection_reverse_bytes_equal": True,
            "new_search_admission_tested_here": False,
            "new_search_types_unconstructible_and_all_operations_refuse": True},
        "form_history_legacy_boundary": {
            "actual_current_history_guard_retained_verbatim": True,
            "before_observation_is_final_null": True,
            "image_admission_endpoint_always_throws": True,
            "native_app_false_and_active_native_task_null": True,
            "new_form_history_admission_tested_here": False},
        "web_fixture_boundary": "Type-only WebTaskDomain; every Web capability method throws",
        "native_app_fixture_boundary": "Real DTO/domain compile; all NativeAppSession operations/constructors throw in this original non-native prompt gate",
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
