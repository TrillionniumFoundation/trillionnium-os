package org.trillionnium.hepta.local;

import android.graphics.Rect;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.FixedIntentTarget;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Frame;

/** Original v49 premature-success choices, replayed through actual completion,
 * prompt and grammar code. Positive completion and controller IO are explicit
 * host fakes. No original failed phone task is promoted to a successful one. */
public final class CompletionStatusHostTest {
    private static final String FIXTURE_SHA="1e07f76bfff89c2038d2f0eaa3b6108fadd9e6e8efbd2dd9cc43d1fac1e3c12c";
    private static final String TASK="12e1318c279c4e268686bc0eec900f6f";
    private static final String RESULT_SHA="92a810f27f7c8182a4f7704baf595566a49f4aa4ff57089f3dc2e8cd3dd11c5c";
    private static final String OWNER_SHA="f0b0dbcf566a3a6072979f7a12b2e20dd1add9b36ceaed1198ef436d9f6f4ab0";
    private static final String BODY="Hepta-v49r1-a11668888e73。购物清单：牛奶、鸡蛋、面包。";
    // Exact existing owner-contract fixture, copied to avoid adding its separate UI test runner.
    private static final String CLOCK_OWNER="先只读查找手机上安装的时钟应用，再打开它并停留在主页面；只查找、打开和结束，不点击、不输入，不新建、修改、启停或删除任何闹钟、计时器或秒表。若打开后不是主页面，停止并说明。";
    private static final String P=NotesCompletionEvidence.NOTES;
    private static JSONObject files;
    private static String owner;
    private static int checks, sequence=7000;
    private static final List<Object> cases=new ArrayList<Object>();
    interface Call { void run() throws Exception; }

    private static void check(boolean ok,String reason) {
        checks++;
        if(!ok)throw new AssertionError(reason);
    }
    private static String id(){return TaskCompletionGateHostTest.id(++sequence);}
    private static Object field(Object object,String name)throws Exception{
        Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(object);
    }
    private static Object invoke(Method m,Object target,Object... args)throws Exception{
        m.setAccessible(true);
        try{return m.invoke(target,args);}
        catch(InvocationTargetException e){if(e.getCause() instanceof Exception)throw (Exception)e.getCause();if(e.getCause() instanceof Error)throw (Error)e.getCause();throw e;}
    }
    private static void deniedCompletion(Call call,String why)throws Exception{
        try{call.run();}
        catch(ActionDecision.InvalidActionException expected){check(true,why);return;}
        throw new AssertionError("expected independent completion-status refusal: "+why);
    }
    private static void deniedBinding(Call call,String why)throws Exception{
        try{call.run();}
        catch(Exception expected){
            if(expected instanceof TaskAuthorization.Violation||expected instanceof IllegalArgumentException){check(true,why);return;}
            throw expected;
        }
        throw new AssertionError("expected immutable task/OWNER refusal: "+why);
    }
    private static String text(String name)throws Exception{
        JSONObject row=files.getJSONObject(name);String value=row.getString("raw_utf8");
        check(row.getString("sha256").equals(ObservedImeEnter.hash(value))
                &&row.getInt("bytes")==value.getBytes(StandardCharsets.UTF_8).length,
                "exact original archived bytes: "+name);
        return value;
    }
    private static JSONObject raw(String name)throws Exception{return new JSONObject(text(name));}
    private static PhoneObservation phone(JSONObject value)throws Exception{
        // The existing helper only reconstructs recorded IO. The v49 editor
        // uses direct text; no synthetic child-label provenance is inferred.
        return (PhoneObservation)invoke(NotesEditorPhaseHostTest.class.getDeclaredMethod("phone",JSONObject.class),null,value);
    }
    private static Frame frame(PhoneObservation value)throws Exception{
        return (Frame)invoke(LocalTaskController.class.getDeclaredMethod("completionFrame",PhoneObservation.class),null,value);
    }
    private static Frame frame(JSONObject value)throws Exception{return frame(phone(value));}
    @SuppressWarnings("unchecked") private static Map<String,Object> map(JSONObject value)throws Exception{
        return (Map<String,Object>)invoke(LocalTaskController.class.getDeclaredMethod("completionFixed",JSONObject.class),null,value);
    }
    private static JSONObject data(String prompt)throws Exception{
        check(prompt.startsWith("UNTRUSTED_DATA\n"),"real controller data framing");
        return new JSONObject(prompt.substring("UNTRUSTED_DATA\n".length(),prompt.indexOf("\nOWNER\n")));
    }
    private static Map<String,FixedIntentTarget> targets(){
        Map<String,FixedIntentTarget> out=new LinkedHashMap<String,FixedIntentTarget>();
        out.put("notes.create",new FixedIntentTarget("notes.create","Moto 笔记",10382,null));
        out.put("web.search",new FixedIntentTarget("web.search","浏览器",10383,null));
        return out;
    }
    private static Object prompt(String instruction,PhoneObservation observed,TaskAuthorization.Gate authority,
            TaskCompletionGate completion,NotesTaskPhaseGuard phase)throws Exception{
        Map<String,String> apps=new LinkedHashMap<String,String>();
        apps.put(P,"Moto 笔记");apps.put("org.trillionnium.hepta.local","Hepta");
        apps.put(targets().get("web.search").packageName,"浏览器");
        for(Method m:LocalTaskController.class.getDeclaredMethods())
            if("prompt".equals(m.getName())&&m.getParameterTypes()[m.getParameterTypes().length-1]==NotesTaskPhaseGuard.class)
                return invoke(m,null,instruction,new AppCatalogueRanker(apps,instruction).search("",0),observed,
                        new JSONArray(),null,null,null,new LocalRuntimeConfig(ModelProfile.LFM3,"npu",8192,4),
                        new RepeatActionGuard(),new SameStateNoEffectGuard(),authority.frame(),null,targets(),completion,phase);
        throw new AssertionError("actual controller prompt overload unavailable");
    }
    private static String decision(Frame current,String action,String status)throws Exception{
        JSONObject row=new JSONObject().put("reason","explicit host test choice").put("action",action)
                .put("observation_id",current.observationId).put("package",current.packageName);
        if("done".equals(action))row.put("status",status).put("summary","host test outcome, not phone success");
        return row.toString();
    }
    private static ActionDecision parsed(String value)throws Exception{
        return ActionDecision.parse(value,ActionDecision.FIXED_INTENT_ACTION_SCHEMA);
    }
    private static String canonical(ActionDecision value)throws Exception{
        // Canonical key order is schema order; all original semantic fields stay
        // exact and the source model-output bytes remain separately hash-bound.
        return new JSONObject().put("reason",value.reason).put("action",value.action)
                .put("observation_id",value.observationId).put("package",value.packageName)
                .put("status",value.status).put("summary",value.summary).toString();
    }
    private static void grammar(String name,String grammar,String json,boolean accepted){
        Map<String,Object> row=new LinkedHashMap<String,Object>();
        row.put("name",name);row.put("grammar",grammar);row.put("json",json);row.put("accepted",accepted);cases.add(row);
    }
    private static void grammar(String name,DecisionGrammar grammar,String json,boolean accepted){
        grammar(name,grammar.text,json,accepted);
    }
    @SuppressWarnings("unchecked") private static void postparse(Object built,ActionDecision action,TaskAuthorization.Gate authority)throws Exception{
        DecisionGrammar grammar=(DecisionGrammar)field(built,"grammar");
        grammar.requireCompletionStatus(action);
        NotesTaskPhaseGuard.Domain domain=(NotesTaskPhaseGuard.Domain)field(built,"phaseDomain");
        ActionPolicy.validateAuthorizedDecision(action,domain.projection.packageName,
                (Set<String>)field(built,"appPackages"),grammar.targets,grammar.appLabels,authority,grammar.authorization,grammar.fixedIntentTargets);
        invoke(built.getClass().getDeclaredMethod("requireTextOnlyClick",ActionDecision.class),built,action);
        domain.requireCurrent(action);
        ((CalculatorTaskInputGuard.Domain)field(built,"calculatorDomain")).requireCurrent(action);
    }
    private static TaskCompletionGate recordedCreate()throws Exception{
        JSONObject installed=raw("completion-installed-identity.json");
        Map<String,String> hashes=new LinkedHashMap<String,String>();
        for(Map.Entry<String,Object> e:map(installed.getJSONObject("apk_hashes")).entrySet())hashes.put(e.getKey(),(String)e.getValue());
        TaskCompletionGate completion=new TaskCompletionGate(TASK,owner,TaskAuthorization.parse(owner));
        completion.bindInstalled(new NotesCompletionEvidence.Installed(installed.getString("package"),installed.getInt("uid"),hashes));
        JSONObject receipt=raw("step-01-action.json");
        ActionDecision create=parsed(receipt.getJSONObject("action").toString());
        check("notes.create".equals(create.action)&&BODY.equals(create.text),"actual first choice contains full immutable owner body");
        Frame before=frame(raw("step-01-before.json")),after=frame(raw("step-01-after.json"));
        completion.observed(before);
        completion.action(1,receipt.getString("model_run_id"),create,receipt.getBoolean("accepted"),receipt.getBoolean("dispatched"),receipt.getBoolean("stale"),
                before,after,map(receipt.getJSONObject("fixed_intent")));
        check(Boolean.TRUE.equals(completion.prompt(after).get("notes_launch_observed"))
                &&Boolean.TRUE.equals(completion.prompt(after).get("editor_body_observed"))&&!completion.verified(after),
                "actual new entry and full body do not establish save/list/reopen");
        return completion;
    }
    private static void recordedPrematureChoices()throws Exception{
        TaskCompletionGate completion=recordedCreate();TaskAuthorization auth=TaskAuthorization.parse(owner);
        TaskAuthorization.Gate authority=auth.bind(TASK);NotesTaskPhaseGuard phase=new NotesTaskPhaseGuard(TASK,auth);
        for(int step:new int[]{2,3}){
            PhoneObservation observed=phone(raw(String.format(java.util.Locale.ROOT,"step-%02d-before.json",step)));Frame current=frame(observed);
            completion.observed(current);
            String oldPrompt=text(String.format(java.util.Locale.ROOT,"step-%02d-prompt.txt",step));
            check(oldPrompt.endsWith("\nOWNER\n"+owner),"original immutable OWNER remains exact");
            JSONObject oldCompletion=data(oldPrompt).getJSONObject("completion");
            check(oldCompletion.getBoolean("editor_body_observed")&&!oldCompletion.getBoolean("list_observed")
                    &&!oldCompletion.getBoolean("same_list_item_reopened"),"original phone prompt already disclosed missing list/reopen");
            ActionDecision original=parsed(text(String.format(java.util.Locale.ROOT,"step-%02d-model-action.json",step)));
            check("done".equals(original.action)&&"success".equals(original.status)
                    &&current.observationId.equals(original.observationId)&&P.equals(original.packageName),
                    "actual premature success decision belongs to this exact observed editor");
            JSONObject receipt=raw(String.format(java.util.Locale.ROOT,"step-%02d-action.json",step));
            String actualRun=step==2?"f8e1799d9ba443d28439920d117f0c78":"914ced0dc58647bca9abb4d37a31009c";
            check(actualRun.equals(receipt.getString("model_run_id"))&&receipt.getBoolean("model_issued")
                    &&receipt.getBoolean("accepted")&&!receipt.getBoolean("dispatched")&&!receipt.getBoolean("stale")
                    &&canonical(original).equals(canonical(parsed(receipt.getJSONObject("action").toString()))),
                    "original raw model choice and admitted no-effect action receipt are the same actual request");
            Object built=prompt(owner,observed,authority,completion,phase);DecisionGrammar grammar=(DecisionGrammar)field(built,"grammar");
            JSONObject projected=data((String)field(built,"text")).getJSONObject("completion");
            check(!completion.verified(current)&&!grammar.successAllowed&&!projected.getBoolean("done_success_eligible"),
                    "real current gate, immutable grammar and prompt agree success is unavailable");
            check(new TreeSet<String>(Arrays.asList("back","wait","done")).equals(new TreeSet<String>(grammar.actions)),
                    "existing editor phase retains only explicit back/wait/outcome choices");
            check(new TreeSet<String>(Arrays.asList("partial","failure")).equals(strings(projected.getJSONArray("allowed_done_statuses"))),
                    "prompt does not offer a success claim");
            String prefix="original-v49-step-"+step+"-";
            grammar(prefix+"old-success-was-generatable",text(String.format(java.util.Locale.ROOT,"step-%02d-grammar.gbnf",step)),canonical(original),true);
            grammar(prefix+"new-success-unavailable",grammar,canonical(original),false);
            deniedCompletion(()->grammar.requireCompletionStatus(original),prefix+"grammar-independent postparse refusal");
            deniedCompletion(()->postparse(built,original,authority),prefix+"complete postparse cannot escape");
            for(String status:new String[]{"partial","failure"}){
                String json=decision(current,"done",status);grammar(prefix+status,grammar,json,true);postparse(built,parsed(json),authority);
            }
            String back=decision(current,"back",null);grammar(prefix+"back-is-a-choice",grammar,back,true);postparse(built,parsed(back),authority);
            check(!completion.verified(current),"checking a back choice never fabricates a dispatched save action");
        }
    }
    private static Set<String> strings(JSONArray values)throws Exception{
        Set<String> out=new TreeSet<String>();for(int i=0;i<values.length();i++)out.add((String)values.get(i));return out;
    }
    private static PhoneObservation syntheticEditor(Frame value){
        List<PhoneObservation.Node> nodes=Arrays.asList(
                TaskCompletionGateHostTest.row("n0",P,TaskCompletionGateHostTest.BODY,"",new Rect(10,100,600,500),true,true,false),
                TaskCompletionGateHostTest.row("n1",P,"NoteEditor","",new Rect(0,0,1080,2400),false,false,true));
        int[] bounds={0,0,1080,2400};
        return new PhoneObservation(value.observationId,P,1,1080,2400,0,value.windowId,new Rect(0,0,1080,2400),
                new File("explicit-synthetic-host-io"),TaskCompletionGateHostTest.H,TaskCompletionGateHostTest.H,
                new ObservationState(TaskCompletionGateHostTest.H,ImeVisibility.HIDDEN),
                ObservedWindowMetadata.observed(bounds,"android.view.View",1,0,bounds,"Moto 笔记"),false,nodes);
    }
    private static void verifiedCurrentAndBinding()throws Exception{
        TaskCompletionGate completion=TaskCompletionGateHostTest.gate();TaskCompletionGateHostTest.chain(completion,false);
        String instruction=TaskCompletionGateHostTest.OWNER;TaskAuthorization auth=TaskAuthorization.parse(instruction);
        TaskAuthorization.Gate authority=auth.bind(TaskCompletionGateHostTest.TASK);
        PhoneObservation observed=syntheticEditor(TaskCompletionGateHostTest.editor());Frame current=frame(observed);
        check(completion.verified(current),"explicit host IO has actual full create/list/same-item/reopen proof");
        Object built=prompt(instruction,observed,authority,completion,new NotesTaskPhaseGuard(TaskCompletionGateHostTest.TASK,auth));
        DecisionGrammar grammar=(DecisionGrammar)field(built,"grammar");JSONObject projected=data((String)field(built,"text")).getJSONObject("completion");
        check(grammar.successAllowed&&projected.getBoolean("done_success_eligible"),"current verified completion enables success");
        for(String status:new String[]{"success","partial","failure"}){
            String json=decision(current,"done",status);grammar("synthetic-verified-current-"+status,grammar,json,true);
            postparse(built,parsed(json),authority);
        }
        TaskCompletionGate foreignTask=new TaskCompletionGate(id(),instruction,TaskAuthorization.parse(instruction));
        deniedBinding(()->prompt(instruction,observed,authority,foreignTask,new NotesTaskPhaseGuard(TaskCompletionGateHostTest.TASK,auth)),
                "another task cannot donate completion state");
        String another=TaskCompletionGateHostTest.owner("不同的正文。");
        TaskCompletionGate foreignOwner=new TaskCompletionGate(TaskCompletionGateHostTest.TASK,another,TaskAuthorization.parse(another));
        deniedBinding(()->prompt(instruction,observed,authority,foreignOwner,new NotesTaskPhaseGuard(TaskCompletionGateHostTest.TASK,auth)),
                "another immutable owner cannot donate completion state");
        PhoneObservation changed=phone(raw("step-01-before.json"));Frame changedFrame=frame(changed);
        Object stale=prompt(instruction,changed,authority,completion,new NotesTaskPhaseGuard(TaskCompletionGateHostTest.TASK,auth));
        DecisionGrammar staleGrammar=(DecisionGrammar)field(stale,"grammar");
        check(!completion.verified(changedFrame)&&!staleGrammar.successAllowed
                &&!data((String)field(stale,"text")).getJSONObject("completion").getBoolean("done_success_eligible"),
                "past verified editor does not enable success on an unrelated current frame");
        String oldSuccess=decision(changedFrame,"done","success");
        grammar("previous-proof-unrelated-current-frame",staleGrammar,oldSuccess,false);
        deniedCompletion(()->staleGrammar.requireCompletionStatus(parsed(oldSuccess)),"current observation controls eligibility");
        eligibilityIntersection(grammar,current);
    }
    private static void eligibilityIntersection(DecisionGrammar base,Frame current)throws Exception{
        TaskAuthorization.Frame ordinary=TaskAuthorization.parse(TaskCompletionGateHostTest.OWNER).bind(TaskCompletionGateHostTest.TASK).frame();
        TaskAuthorization.Frame clock=TaskAuthorization.parse(CLOCK_OWNER).bind(TaskCompletionGateHostTest.TASK).frame();
        check(ordinary.successAllowed()&&!clock.successAllowed(),"existing literal owner contract supplies an independent authority refusal");
        for(int variant=0;variant<3;variant++){
            boolean eligible=variant!=1;TaskAuthorization.Frame authority=variant==0?clock:ordinary;boolean allowed=variant==2;
            for(boolean fixed:new boolean[]{false,true}){
                Set<String> shown=new TreeSet<String>(base.appLabels.labels.keySet());
                Set<String> none=Collections.emptySet();Set<String> taskTools=new TreeSet<String>(Arrays.asList("back","wait","done"));
                DecisionGrammar grammar=fixed?DecisionGrammar.createFixedIntentAuthorized(current.observationId,current.packageName,shown,none,none,
                        Collections.<String,ObservedScrollActions>emptyMap(),Collections.<String,ObservedImeEnter>emptyMap(),base.targets,base.appLabels,authority,false,
                        Collections.<String,FixedIntentTarget>emptyMap(),Collections.<String,String>emptyMap(),taskTools,eligible)
                        :DecisionGrammar.createImeAuthorized(current.observationId,current.packageName,shown,none,none,
                        Collections.<String,ObservedScrollActions>emptyMap(),Collections.<String,ObservedImeEnter>emptyMap(),base.targets,base.appLabels,authority,false,taskTools,eligible);
                check(grammar.successAllowed==allowed,"both grammar protocols intersect completion and original owner authority");
                for(String status:new String[]{"success","partial","failure"}){
                    String json=decision(current,"done",status);boolean accepted=!"success".equals(status)||allowed;
                    grammar("intersection-"+variant+"-"+fixed+"-"+status,grammar,json,accepted);
                    if(accepted)grammar.requireCompletionStatus(parsed(json));
                    else deniedCompletion(()->grammar.requireCompletionStatus(parsed(json)),"independent intersection "+variant);
                }
            }
        }
    }
    private static void unsupportedAndAbsent()throws Exception{
        PhoneObservation observed=phone(raw("step-02-before.json"));Frame current=frame(observed);
        for(String instruction:new String[]{TaskCompletionGateHostTest.WEB,"读出当前页面的标题，不要点击或输入。"}){
            TaskAuthorization auth=TaskAuthorization.parse(instruction);TaskCompletionGate completion=new TaskCompletionGate(TASK,instruction,auth);completion.observed(current);
            Object built=prompt(instruction,observed,auth.bind(TASK),completion,new NotesTaskPhaseGuard(TASK,auth));DecisionGrammar grammar=(DecisionGrammar)field(built,"grammar");
            check(!completion.verified(current)&&!grammar.successAllowed&&!data((String)field(built,"text")).getJSONObject("completion").getBoolean("done_success_eligible"),
                    "unsupported independent result provider does not offer success");
            String json=decision(current,"done","success");grammar("unsupported-"+completion.contract.kind,grammar,json,false);
            deniedCompletion(()->grammar.requireCompletionStatus(parsed(json)),"unsupported goal completion");
        }
        TaskAuthorization auth=TaskAuthorization.parse(owner);
        Object absent=prompt(owner,observed,auth.bind(TASK),null,new NotesTaskPhaseGuard(TASK,auth));
        DecisionGrammar grammar=(DecisionGrammar)field(absent,"grammar");
        check(!grammar.successAllowed,"missing gate is fail-closed");
        String json=decision(current,"done","success");grammar("absent-completion-gate",grammar,json,false);
        deniedCompletion(()->grammar.requireCompletionStatus(parsed(json)),"absent gate completion");
    }
    private static final class OutcomeModel implements LocalInference{
        final QualificationScopeHostTest.Env env;final String status;final TaskCompletionGateHostTest.Model io;
        int calls,ends;String task;
        OutcomeModel(QualificationScopeHostTest.Env env,String status){this.env=env;this.status=status;io=new TaskCompletionGateHostTest.Model(env,"draft",TaskCompletionGateHostTest.DRAFT_OWNER);io.setup();}
        public LocalRuntimeConfig configuration(){return env.runtime;}
        public void beginTask(String id){task=id;}
        public TaskCleanup endTask(){ends++;return new TaskCleanup(true,true,true,0,TaskCompletionGateHostTest.id(7999),task,true,TaskCompletionGateHostTest.H);}
        public Handle generate(String prompt,String system,File image,DecisionGrammar grammar,int maximum,long timeout,Callback callback){
            calls++;
            try{
                check(!grammar.successAllowed&&!data(prompt).getJSONObject("completion").getBoolean("done_success_eligible"),"actual model request excludes unverified success");
                String json;
                if(calls==1){
                    FixedIntentTarget target=grammar.fixedIntentTargets.get("notes.create");check(target!=null,"ordinary model can still choose the exact-body creation tool");
                    json=new JSONObject().put("reason","explicit synthetic model creation").put("action","notes.create").put("observation_id",grammar.observationId)
                            .put("app_label",ObservedAppLabels.project(target.appLabel)).put("package",target.packageName).put("text",TaskCompletionGateHostTest.BODY).toString();
                }else{
                    check(calls==2&&grammar.actions.contains("back"),"back remains an offered choice, never a scheduled automatic effect");
                    json=new JSONObject().put("reason","explicit synthetic model stop").put("action","done").put("observation_id",grammar.observationId)
                            .put("package",grammar.currentPackage).put("status",status).put("summary","model elects to stop without claiming save").toString();
                }
                grammar("actual-controller-"+status+"-"+calls,grammar,json,true);callback.onSuccess(json,TaskCompletionGateHostTest.id(calls+7100));
            }catch(Exception e){throw new IllegalStateException(e);}
            return ()->{};
        }
    }
    private static void controllerKeepsModelChoice(Path out)throws Exception{
        QualificationScopeHostTest.output=out;Files.createDirectories(out);
        for(String status:new String[]{"partial","failure"}){
            try(QualificationScopeHostTest.Env env=new QualificationScopeHostTest.Env(false)){
                TaskCompletionGateHostTest.installPackage(env,"notes.create");TaskCompletionGateHostTest.installPackage(env,"web.search");
                OutcomeModel model=new OutcomeModel(env,status);env.controller=new LocalTaskController(env.service,model);
                CountDownLatch finished=new CountDownLatch(1);LocalTaskController.TaskResult[] result={null};
                // This explicit no-save contract has no workflow authority.
                // Full save/list/reopen contracts have their own actual
                // controller/tool-child integration tests in v51.
                check(env.controller.start(TaskCompletionGateHostTest.DRAFT_OWNER,null,new LocalTaskController.Listener(){
                    public void onState(String state){}
                    public void onFinished(LocalTaskController.TaskResult value){result[0]=value;finished.countDown();}
                }),"actual controller starts explicit synthetic IO task");
                check(finished.await(10,TimeUnit.SECONDS),"bounded host controller completion");
                LocalTaskController.TaskResult value=result[0];
                check(value!=null&&!value.completionVerified&&!value.modelReportedSuccess&&value.cleanupKnown,"partial/failure choice never becomes success");
                check(("partial".equals(status)?"partial":"failed").equals(value.status),"model-selected non-success terminal follows existing status mapping: "+status+" / "+value.status);
                check(model.calls==2&&model.ends==1&&env.service.opens==1&&env.service.navigations==0&&env.service.node.actions==0,
                        "one model-bound create, no automatic Back/click, one teardown");
            }
        }
    }
    public static void main(String[] args)throws Exception{
        Path fixture=Paths.get(args[0]),out=Paths.get(args[1]);Files.createDirectories(out);
        byte[] bytes=Files.readAllBytes(fixture);
        check(FIXTURE_SHA.equals(ObservedImeEnter.hash(new String(bytes,StandardCharsets.UTF_8))),"frozen original v49 trace SHA");
        JSONObject document=new JSONObject(new String(bytes,StandardCharsets.UTF_8));files=document.getJSONObject("files");
        check(TASK.equals(document.getString("task_id"))&&RESULT_SHA.equals(document.getString("original_result_sha256")),"original failed phone task and receipt bound");
        JSONObject actual=raw("RESULT.json");
        check(RESULT_SHA.equals(files.getJSONObject("RESULT.json").getString("sha256"))
                &&TASK.equals(actual.getString("task_id"))&&!actual.getBoolean("qualified")
                &&"partial".equals(actual.getJSONObject("terminal_session").getString("status"))
                &&!actual.getJSONObject("terminal_session").getBoolean("completion_verified"),
                "the original phone receipt remains partial and unqualified");
        owner=raw("owner.json").getString("instruction");
        check(OWNER_SHA.equals(ObservedImeEnter.hash(owner))&&BODY.equals(TaskCompletionGate.Contract.parse(owner,TaskAuthorization.parse(owner)).body),
                "actual immutable owner and exact full body");
        recordedPrematureChoices();verifiedCurrentAndBinding();unsupportedAndAbsent();controllerKeepsModelChoice(out.resolve("controller"));
        Files.write(out.resolve("grammar-cases.json"),new JSONArray(cases).toString().getBytes(StandardCharsets.UTF_8));
        check(FIXTURE_SHA.equals(ObservedImeEnter.hash(new String(Files.readAllBytes(fixture),StandardCharsets.UTF_8))),"original fixture unchanged");
        System.out.println("PASS "+checks+" completion-status assertions; original_v49_partial=true; synthetic_positive_and_controller_io=true; phone_tested=false");
        System.out.println("completion_status_grammar_cases="+cases.size());
    }
}

