package org.trillionnium.hepta.local;

import android.content.Intent;
import android.os.Handler;
import android.view.accessibility.AccessibilityNodeInfo;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Recreated independent tests after executor replacement. No previous test identity is claimed.
 * Executes actual extracted Service/MainActivity/Session and complete Controller/authorization.
 * Android IO, UI acquisition and inference are explicit fakes; no phone/native inference claim. */
public final class OwnerAuthorizationWiringHostTest {
    static final String CLOCK_OWNER="先只读查找手机上安装的时钟应用，再打开它并停留在主页面；只查找、打开和结束，不点击、不输入，不新建、修改、启停或删除任何闹钟、计时器或秒表。若打开后不是主页面，停止并说明。";
    static final String CLOCK="com.android.deskclock";
    static final String SETTINGS=QualificationScopeHostTest.SETTINGS;
    static final String CALC=QualificationScopeHostTest.CALC;
    static final String RUN1="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",RUN2="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2",RUN3="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3";
    static final List<JSONObject> results=new ArrayList<JSONObject>();
    static Path output;static String selectedCase;
    interface Case { void run() throws Exception; }
    static void check(boolean value,String why){if(!value)throw new AssertionError(why);}
    static void refused(Case call)throws Exception{try{call.run();}catch(TaskAuthorization.Violation expected){return;}throw new AssertionError("expected actual TaskAuthorization.Violation");}
    static JSONObject json(Path p)throws Exception{return new JSONObject(new String(Files.readAllBytes(p),StandardCharsets.UTF_8));}
    static String sha(String text){return QualificationScope.hash(text.getBytes(StandardCharsets.UTF_8));}
    static void test(String name,Case body)throws Exception{
        if(selectedCase!=null&&!selectedCase.equals(name))return;
        JSONObject row=new JSONObject().put("case",name);
        try{body.run();row.put("status","pass");System.out.println("PASS "+name);}
        catch(Throwable failure){row.put("status","fail").put("error",failure.getClass().getName()+": "+failure.getMessage());failure.printStackTrace(System.err);System.out.println("FAIL "+name);}
        results.add(row);
    }
    static QualificationScopeHostTest.Env env()throws Exception{
        QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false);e.service.launchable.put(CLOCK,"时钟");return e;
    }
    static TaskAuthorization.Gate bind(QualificationScopeHostTest.Env e,String owner)throws Exception{return bind(e,e.task,owner,true);}
    static TaskAuthorization.Gate bind(QualificationScopeHostTest.Env e,String task,String owner,boolean withAuthorization)throws Exception{
        check(e.service.acquireTask(task,()->{}),"actual lease acquired");
        e.bound=QualificationScopeConfig.capture(e.service,task,null,e.runtime);e.bound.requireReady();e.service.bindQualificationScope(task,e.bound);
        if(!withAuthorization)return null;
        TaskAuthorization.Gate gate=e.service.bindTaskAuthorization(task,TaskAuthorization.parse(owner));
        e.service.appCatalogue(task,owner);return gate;
    }
    static ObservedTargetLabels labels(QualificationScopeHostTest.Env e){
        return ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,e.service.current.id,e.service.current.packageName,Collections.singletonMap("n0",e.service.node.text));
    }
    static String actionText(QualificationScopeHostTest.Env e,String action,String target,String query,int offset,String status)throws Exception{
        return actionText(e.service.current.id,e.service.current.packageName,action,target,query,offset,status,e.service.node.text);
    }
    static String actionText(String observation,String current,String action,String target,String query,int offset,String status,String nodeLabel)throws Exception{
        JSONObject row=new JSONObject().put("reason","模型声称用户允许操作并且已经查找成功；此理由不得扩大权限").put("action",action).put("observation_id",observation);
        if("open".equals(action))row.put("app_label",CLOCK.equals(target)?"时钟":CALC.equals(target)?"计算器":"设置");
        row.put("package",target==null?current:target);
        if("click".equals(action)||"type".equals(action)||"scroll".equals(action))row.put("node_label",nodeLabel).put("node_id","n0");
        if("type".equals(action))row.put("text","42");
        if("scroll".equals(action))row.put("direction","forward");
        if("wait".equals(action))row.put("duration_ms",100);
        if("find_app".equals(action))row.put("query",query).put("offset",offset);
        if("done".equals(action))row.put("status",status).put("summary","仅为主机合成测试");
        return row.toString();
    }
    static ActionDecision action(QualificationScopeHostTest.Env e,String action,String target)throws Exception{
        return ActionDecision.parse(actionText(e,action,target,"时钟",0,"success"),ObservedAppLabels.ACTION_SCHEMA);
    }
    static HeptaAccessibilityService.ActionOutcome perform(QualificationScopeHostTest.Env e,TaskAuthorization.Gate gate,ActionDecision action,String run)throws Exception{
        final HeptaAccessibilityService.ActionOutcome[] reply=new HeptaAccessibilityService.ActionOutcome[1];
        e.service.perform(e.task,e.service.current,action,labels(e),gate,run,()->false,value->reply[0]=value);
        check(reply[0]!=null,"expected synchronous fake-IO callback");return reply[0];
    }
    static void denied(QualificationScopeHostTest.Env e,HeptaAccessibilityService.ActionOutcome r){
        check(!r.accepted&&!r.dispatched&&!r.stale&&e.service.effects()==0,"denial must have no actual effect API calls");
    }
    static void proof(HeptaAccessibilityService.ActionOutcome r,TaskAuthorization.Gate gate,String run,String action,boolean allowed)throws Exception{
        JSONObject value=r.taskAuthorization;check(value!=null,"callback authorization evidence required");
        check(gate.taskId.equals(value.getString("task_id"))&&gate.authorization.sha256.equals(value.getString("authorization_sha256")),"callback same task/contract");
        JSONObject last=value.getJSONObject("last_check");
        check(run.equals(last.getString("model_run_id"))&&action.equals(last.getString("action"))&&last.getBoolean("allowed")==allowed,"last check actual action/run/result");
    }
    static void successfulLookup(QualificationScopeHostTest.Env e,TaskAuthorization.Gate gate)throws Exception{
        HeptaAccessibilityService.ActionOutcome result=perform(e,gate,action(e,"find_app",e.service.current.packageName),RUN1);
        check(result.accepted&&!result.dispatched&&result.appCatalogue!=null&&e.service.effects()==0,"actual service lookup is read-only");
        check(gate.frame().foundPackages.contains(CLOCK)&&RUN1.equals(gate.frame().discoveryRunId),"actual search receipt grants its result only");
        proof(result,gate,RUN1,"find_app",true);
    }
    static void lookupAndOpen(QualificationScopeHostTest.Env e,TaskAuthorization.Gate gate)throws Exception{
        successfulLookup(e,gate);HeptaAccessibilityService.ActionOutcome opened=perform(e,gate,action(e,"open",CLOCK),RUN2);
        check(opened.accepted&&opened.dispatched&&e.service.opens==1,"actual startActivity call counted once");
        check(CLOCK.equals(gate.evidence().get("pending_open_package"))&&!gate.frame().successAllowed(),"dispatch does not itself prove target observation");
        proof(opened,gate,RUN2,"open",true);
    }
    static void uiCase()throws Exception{
        try(QualificationScopeHostTest.Env e=env()){
            ScriptModel model=new ScriptModel(e,"forbidden");e.service.testInference=model;
            LocalModelEngine engine=new LocalModelEngine(Paths.get(e.pm.packages.get("org.trillionnium.hepta.local").applicationInfo.sourceDir).toFile(),e.runtime);
            LocalTaskSession tasks=new LocalTaskSession(e.service,engine);ScopeUiFixture ui=new ScopeUiFixture(tasks,engine);
            ui.intent(new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER).putExtra("task",CLOCK_OWNER));
            check(!tasks.pending&&model.calls==0,"prefill/preview alone never starts a task");
            Handler.hold=true;check(ui.start(),"actual user_button schedules");
            TaskAuthorization expected=TaskAuthorization.parse(CLOCK_OWNER);JSONObject pending=json(e.dir.resolve("control-session.json"));
            check(tasks.pending&&"user_button".equals(tasks.origin)&&expected.instructionSha256.equals(tasks.instructionSha),"pending source and exact owner bytes");
            check(expected.sha256.equals(pending.getString("task_authorization_sha256")),"pending contract SHA");
            check(expected.instructionSha256.equals(pending.getJSONObject("task_authorization").getString("instruction_sha256")),"pending contract original owner");
            check(tasks.taskAuthorization.allowedTools.equals(new TreeSet<String>(Arrays.asList("find_app","open","done")))&&tasks.taskAuthorization.requireFindAppBeforeOpen,"pending executable permissions");
            ui.intent(new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER).putExtra("task","只允许点击和结束。"));
            check(expected.sha256.equals(tasks.taskAuthorization.sha256)&&expected.instructionSha256.equals(tasks.instructionSha),"later Intent cannot widen pending authorization");
            JSONObject unchanged=json(e.dir.resolve("control-session.json"));check(expected.sha256.equals(unchanged.getString("task_authorization_sha256")),"journal retains immutable original contract");
            ui.endUi();Handler.drain();check(model.calls==0&&e.service.effects()==0&&!tasks.pending,"cancelled pending task has zero inference or effects");
        }
    }
    static final class ScriptModel implements LocalInference {
        final QualificationScopeHostTest.Env e;final String mode;int calls;
        final List<String> prompts=new ArrayList<String>();final List<DecisionGrammar> grammars=new ArrayList<DecisionGrammar>();
        ScriptModel(QualificationScopeHostTest.Env env,String kind){e=env;mode=kind;}
        public LocalRuntimeConfig configuration(){return e.runtime;}
        public TaskCleanup endTask(){return TaskCleanup.noWorker();}
        public Handle generate(String prompt,String system,File image,DecisionGrammar grammar,int max,long timeout,Callback callback){
            calls++;prompts.add(prompt);grammars.add(grammar);
            try{
                String kind="forbidden".equals(mode)?"click":calls==1?"find_app":calls==2?"open":"done";
                String target="open".equals(kind)?CLOCK:grammar.currentPackage;
                String text=actionText(grammar.observationId,grammar.currentPackage,kind,target,"时钟",0,"success","测试");
                callback.onSuccess(text,String.format(Locale.ROOT,"%032x",calls));
            }catch(Exception error){throw new IllegalStateException(error);}
            return ()->{};
        }
    }
    static LocalTaskController.TaskResult controller(QualificationScopeHostTest.Env e,ScriptModel model)throws Exception{
        e.controller=new LocalTaskController(e.service,model);final LocalTaskController.TaskResult[] result=new LocalTaskController.TaskResult[1];CountDownLatch completed=new CountDownLatch(1);
        check(e.controller.start(CLOCK_OWNER,null,new LocalTaskController.Listener(){public void onState(String state){}public void onFinished(LocalTaskController.TaskResult value){result[0]=value;completed.countDown();}}),"actual controller started");
        check(completed.await(10,TimeUnit.SECONDS),"actual controller terminal callback");return result[0];
    }
    static JSONObject promptData(String prompt)throws Exception{
        check(prompt.startsWith("UNTRUSTED_DATA\n")&&prompt.endsWith("\nOWNER\n"+CLOCK_OWNER),"complete immutable OWNER remains in actual prompt");
        return new JSONObject(prompt.substring("UNTRUSTED_DATA\n".length(),prompt.lastIndexOf("\nOWNER\n")));
    }
    static void controllerIdentity(LocalTaskController.TaskResult result,ScriptModel model)throws Exception{
        TaskAuthorization expected=TaskAuthorization.parse(CLOCK_OWNER);JSONObject owner=json(result.evidenceDirectory.toPath().resolve("owner.json")),terminal=json(result.evidenceDirectory.toPath().resolve("result.json"));
        for(JSONObject value:Arrays.asList(owner,terminal)){
            check(expected.sha256.equals(value.getString("task_authorization_sha256")),"owner/result exact authorization hash");
            JSONObject contract=value.getJSONObject("task_authorization");check(expected.instructionSha256.equals(contract.getString("instruction_sha256"))&&expected.sha256.equals(contract.getString("authorization_sha256")),"owner/result full contract binding");
        }
        for(String text:model.prompts){JSONObject authorization=promptData(text).getJSONObject("task_authorization");
            check(expected.sha256.equals(authorization.getString("authorization_sha256"))&&result.taskId.equals(authorization.getString("task_id")),"every actual prompt is bound to same contract and actual task");}
    }
    public static void main(String[] args)throws Exception{
        if(args.length<1||args.length>2)throw new IllegalArgumentException("output directory and optional exact case required");selectedCase=args.length==2?args[1]:null;output=Paths.get(args[0]);Files.createDirectories(output);QualificationScopeHostTest.output=output;
        test("ordinary_ui_owner_to_pending_contract_immutable",OwnerAuthorizationWiringHostTest::uiCase);
        for(String kind:new String[]{"click","type"})test("direct_service_forbidden_"+kind+"_zero_dispatch",()->{try(QualificationScopeHostTest.Env e=env()){
            TaskAuthorization.Gate gate=bind(e,CLOCK_OWNER);HeptaAccessibilityService.ActionOutcome r=perform(e,gate,action(e,kind,SETTINGS),RUN1);denied(e,r);proof(r,gate,RUN1,kind,false);check(r.taskAuthorization.getBoolean("refused"),"final dispatch refusal is sticky");
        }});
        for(String which:new String[]{"unbound","null_expected","same_task_new_gate","other_task_same_contract"})test("missing_or_foreign_gate_"+which,()->{try(QualificationScopeHostTest.Env e=env()){
            TaskAuthorization.Gate current=bind(e,e.task,"打开时钟。",!"unbound".equals(which));TaskAuthorization.Gate supplied=current;
            if("null_expected".equals(which))supplied=null;
            if("same_task_new_gate".equals(which))supplied=current.authorization.bind(e.task);
            if("other_task_same_contract".equals(which))supplied=current.authorization.bind("22222222222222222222222222222222");
            HeptaAccessibilityService.ActionOutcome r=perform(e,supplied,action(e,"open",CLOCK),RUN1);denied(e,r);
            if(current==null)check(r.taskAuthorization==null,"unbound callback cannot forge authorization");else check(!r.taskAuthorization.getBoolean("callback_lease_current"),"foreign expected Gate rejected");
        }});
        test("same_contract_cross_task_frame_cannot_authorize_policy",()->{try(QualificationScopeHostTest.Env e=env()){
            TaskAuthorization.Gate gate=bind(e,"打开时钟。");TaskAuthorization.Frame foreign=gate.authorization.bind("22222222222222222222222222222222").frame();
            ObservedAppLabels apps=ObservedAppLabels.create(ObservedAppLabels.SCHEMA,e.service.current.id,SETTINGS,Collections.<String,String>emptyMap());
            ActionDecision decision=ActionDecision.parse(actionText(e,"done",SETTINGS,"时钟",0,"failure"),ObservedAppLabels.ACTION_SCHEMA);
            refused(()->ActionPolicy.validateAuthorizedDecision(decision,SETTINGS,Collections.<String>emptySet(),labels(e),apps,gate,foreign));check(e.service.effects()==0,"policy never dispatches");
        }});
        test("initial_catalogue_and_model_reason_do_not_replace_real_find",()->{try(QualificationScopeHostTest.Env e=env()){
            TaskAuthorization.Gate gate=bind(e,CLOCK_OWNER);check(gate.frame().foundPackages.isEmpty(),"initial projection grants no lookup");denied(e,perform(e,gate,action(e,"open",CLOCK),RUN1));
        }});
        test("wrong_required_query_never_grants_open",()->{try(QualificationScopeHostTest.Env e=env()){
            TaskAuthorization.Gate gate=bind(e,CLOCK_OWNER);ActionDecision wrong=ActionDecision.parse(actionText(e,"find_app",SETTINGS,"计算器",0,"success"),ObservedAppLabels.ACTION_SCHEMA);
            HeptaAccessibilityService.ActionOutcome r=perform(e,gate,wrong,RUN1);denied(e,r);check(r.appCatalogue==null&&gate.evidence().get("discovery_run_id")==null,"wrong query was not recorded as successful lookup");
        }});
        for(String which:new String[]{"catalogue","query","offset"})test("real_page_identity_mismatch_"+which+"_grants_nothing",()->{try(QualificationScopeHostTest.Env e=env()){
            TaskAuthorization.Gate gate=bind(e,CLOCK_OWNER);Map<String,String> apps=new LinkedHashMap<String,String>(e.service.launchable);if("catalogue".equals(which))apps.put("org.example.syntheticother","另一个应用");
            AppCatalogueRanker ranker=new AppCatalogueRanker(apps,CLOCK_OWNER);AppCatalogueRanker.Page page=ranker.search("query".equals(which)?"计算器":"时钟","offset".equals(which)?1:0);ActionDecision lookup=action(e,"find_app",SETTINGS);
            refused(()->gate.found(lookup,RUN1,page));check(gate.frame().foundPackages.isEmpty()&&gate.frame().discoveryRunId==null,"mismatched actual ranker page grants no membership");check(e.service.effects()==0,"no Android dispatch");
        }});
        test("empty_actual_search_result_cannot_grant_open",()->{try(QualificationScopeHostTest.Env e=env()){
            e.service.launchable.remove(CLOCK);TaskAuthorization.Gate gate=bind(e,CLOCK_OWNER);HeptaAccessibilityService.ActionOutcome r=perform(e,gate,action(e,"find_app",SETTINGS),RUN1);
            check(r.accepted&&r.appCatalogue.apps.isEmpty()&&gate.frame().foundPackages.isEmpty(),"empty actual search stays empty");denied(e,perform(e,gate,action(e,"open",CLOCK),RUN2));
        }});
        test("actual_lookup_and_open_do_not_alone_allow_success_done",()->{try(QualificationScopeHostTest.Env e=env()){
            TaskAuthorization.Gate gate=bind(e,CLOCK_OWNER);lookupAndOpen(e,gate);HeptaAccessibilityService.ActionOutcome r=perform(e,gate,action(e,"done",SETTINGS),RUN3);
            check(!r.accepted&&!r.dispatched&&e.service.opens==1,"success refused before target observation, original open retained");
        }});
        test("wrong_package_observation_does_not_allow_success_done",()->{try(QualificationScopeHostTest.Env e=env()){
            TaskAuthorization.Gate gate=bind(e,CLOCK_OWNER);lookupAndOpen(e,gate);e.service.requireAuthorizationObservation(e.task,gate,e.service.current);
            check(!gate.frame().successAllowed()&&gate.evidence().get("opened_observation_id")==null,"unrelated Settings observation does not prove Clock opened");
        }});
        test("actual_target_observation_allows_success_done",()->{try(QualificationScopeHostTest.Env e=env()){
            TaskAuthorization.Gate gate=bind(e,CLOCK_OWNER);lookupAndOpen(e,gate);e.service.prepare(CLOCK);e.service.requireAuthorizationObservation(e.task,gate,e.service.current);
            String observed=e.service.current.id;HeptaAccessibilityService.ActionOutcome r=perform(e,gate,action(e,"done",CLOCK),RUN3);
            check(r.accepted&&!r.dispatched&&e.service.opens==1&&observed.equals(r.taskAuthorization.getString("opened_observation_id")),"success bound to actual target observation, not model claim");proof(r,gate,RUN3,"done",true);
        }});
        test("queued_main_cannot_borrow_rebound_same_id_authorization",()->{try(QualificationScopeHostTest.Env e=env()){
            TaskAuthorization.Gate old=bind(e,"只允许打开和结束。");HeptaAccessibilityService.ActionOutcome[] box=new HeptaAccessibilityService.ActionOutcome[1];Handler.holdPosts=true;
            e.service.perform(e.task,e.service.current,action(e,"open",CLOCK),labels(e),old,RUN1,()->false,r->box[0]=r);check(box[0]==null,"actual posted main entry queued");e.service.releaseTask(e.task);
            TaskAuthorization.Gate fresh=bind(e,"只允许查找和结束。");Handler.drain();denied(e,box[0]);check(old.authorization.sha256.equals(box[0].taskAuthorization.getString("authorization_sha256"))&&!box[0].taskAuthorization.getBoolean("callback_lease_current"),"old captured contract, never replacement contract");fresh.ready();
        }});
        for(String kind:new String[]{"click","type","scroll"})test("retire_between_initial_check_and_"+kind+"_api_refuses",()->{try(QualificationScopeHostTest.Env e=env()){
            TaskAuthorization.Gate gate=bind(e,"继续执行任务。");e.service.node.onRefresh=gate::retire;
            HeptaAccessibilityService.ActionOutcome r=perform(e,gate,action(e,kind,SETTINGS),RUN1);denied(e,r);proof(r,gate,RUN1,kind,false);check(e.service.node.refreshes>0,"actual fresh-node path reached before final guard");
        }});
        test("retire_inside_dispatched_open_preserves_actual_side_effect",()->{try(QualificationScopeHostTest.Env e=env()){
            TaskAuthorization.Gate gate=bind(e,"打开时钟。");e.service.effectHook=gate::retire;HeptaAccessibilityService.ActionOutcome r=perform(e,gate,action(e,"open",CLOCK),RUN1);
            check(!r.accepted&&r.dispatched&&e.service.opens==1,"post-startActivity retirement cannot erase dispatched effect");check(r.taskAuthorization.getBoolean("retired"),"retired evidence retained");
        }});
        for(String kind:new String[]{"wait","click","type","scroll","home","open"})test("late_"+kind+"_callback_cannot_use_replacement_gate",()->{try(QualificationScopeHostTest.Env e=env()){
            TaskAuthorization.Gate old=bind(e,"继续执行任务。");HeptaAccessibilityService.ActionOutcome[] box=new HeptaAccessibilityService.ActionOutcome[1];AccessibilityNodeInfo node=e.service.node;Handler.hold=true;
            e.service.perform(e.task,e.service.current,action(e,kind,"open".equals(kind)?CLOCK:SETTINGS),labels(e),old,RUN1,()->false,r->box[0]=r);check(box[0]==null,"actual delayed callback queued");
            int effects=e.service.effects(),reads=node.refreshes;check(effects==("wait".equals(kind)?0:1),"actual pre-retirement dispatch count");e.service.releaseTask(e.task);
            TaskAuthorization.Gate fresh=bind(e,"只允许查找和结束。");node.onRefresh=()->{throw new AssertionError("retired node read");};Handler.drain();
            check(box[0]!=null&&!box[0].accepted&&!box[0].stale&&box[0].dispatched==!"wait".equals(kind),"late callback refuses while preserving existing dispatch");
            JSONObject evidence=box[0].taskAuthorization;check(old.authorization.sha256.equals(evidence.getString("authorization_sha256"))&&evidence.getBoolean("retired")&&!evidence.getBoolean("callback_lease_current"),"callback bound to old gate");
            check(e.service.effects()==effects&&node.refreshes==reads,"no late action or retired text read");fresh.ready();check(!Boolean.TRUE.equals(fresh.evidence().get("refused")),"new gate unpoisoned");
        }});
        test("cancelled_type_callback_preserves_dispatch_and_skips_read",()->{try(QualificationScopeHostTest.Env e=env()){
            TaskAuthorization.Gate gate=bind(e,"继续执行任务。");HeptaAccessibilityService.ActionOutcome[] box=new HeptaAccessibilityService.ActionOutcome[1];AtomicBoolean stopped=new AtomicBoolean();Handler.hold=true;
            e.service.perform(e.task,e.service.current,action(e,"type",SETTINGS),labels(e),gate,RUN1,stopped::get,r->box[0]=r);int reads=e.service.node.refreshes;stopped.set(true);e.service.node.onRefresh=()->{throw new AssertionError("cancelled node read");};Handler.drain();
            check(box[0]!=null&&!box[0].accepted&&box[0].dispatched&&box[0].taskAuthorization.getBoolean("callback_cancelled")&&e.service.node.refreshes==reads&&e.service.node.actions==1,"cancelled callback remains actual one dispatch");
        }});
        test("controller_missing_contract_refuses_before_model_or_lease",()->{try(QualificationScopeHostTest.Env e=env()){
            ScriptModel model=new ScriptModel(e,"forbidden");e.controller=new LocalTaskController(e.service,model);
            refused(()->e.controller.start(CLOCK_OWNER,null,null,new LocalTaskController.Listener(){public void onState(String v){}public void onFinished(LocalTaskController.TaskResult v){throw new AssertionError("missing contract must not start");}}));
            check(model.calls==0&&e.service.effects()==0&&e.service.acquireTask(e.task,()->{}),"missing contract does not start model or retain a lease");
        }});
        test("controller_forbidden_model_click_fails_once_before_dispatch",()->{try(QualificationScopeHostTest.Env e=env()){
            ScriptModel model=new ScriptModel(e,"forbidden");LocalTaskController.TaskResult r=controller(e,model);controllerIdentity(r,model);
            check("failed".equals(r.status)&&!r.modelReportedSuccess&&r.cleanupKnown&&model.calls==1&&e.service.effects()==0,"Owner violation is terminal, not format repair or successful done");
            check(!model.grammars.get(0).actions.contains("click")&&!model.grammars.get(0).actions.contains("type"),"actual prompt grammar already narrows forbidden tools");
            check(!Files.exists(r.evidenceDirectory.toPath().resolve("step-01-action.json")),"rejected proposal never reaches Service action dispatch");
        }});
        test("controller_real_find_open_observation_done_full_evidence_chain",()->{try(QualificationScopeHostTest.Env e=env()){
            ScriptModel model=new ScriptModel(e,"sequence");e.service.effectHook=()->e.service.prepare(CLOCK);LocalTaskController.TaskResult r=controller(e,model);controllerIdentity(r,model);
            check("model_reported_done".equals(r.status)&&r.modelReportedSuccess&&r.cleanupKnown&&model.calls==3&&e.service.opens==1&&e.service.effects()==1,"actual controlled sequence closes with one open");
            Path evidence=r.evidenceDirectory.toPath();TaskAuthorization expected=TaskAuthorization.parse(CLOCK_OWNER);
            for(int step=1;step<=3;step++){
                JSONObject a=json(evidence.resolve(String.format(Locale.ROOT,"step-%02d-action.json",step))),m=json(evidence.resolve(String.format(Locale.ROOT,"step-%02d-model-0.json",step)));
                check(a.getString("model_run_id").equals(m.getString("run_id"))&&expected.sha256.equals(a.getString("task_authorization_sha256")),"action is bound to actual model run and Owner contract");
                JSONObject auth=a.getJSONObject("task_authorization"),last=auth.getJSONObject("last_check");
                check(r.taskId.equals(auth.getString("task_id"))&&a.getString("model_run_id").equals(last.getString("model_run_id"))&&last.getBoolean("allowed")&&auth.getBoolean("callback_lease_current")&&!auth.getBoolean("callback_cancelled"),"actual callback evidence closed");
                JSONObject data=promptData(model.prompts.get(step-1));boolean expectedSuccess=step==3;
                check(data.getJSONObject("task_authorization").getBoolean("success_done_allowed")==expectedSuccess,"success gate only opens after real target observation");
            }
            JSONObject terminal=json(evidence.resolve("result.json")),gate=terminal.getJSONObject("task_authorization");String observed=gate.getString("opened_observation_id");
            JSONObject observation=json(evidence.resolve("scope-observation-"+observed+".json"));
            check(CLOCK.equals(observation.getJSONObject("observation").getString("package"))&&expected.sha256.equals(observation.getJSONObject("task_authorization").getString("authorization_sha256")),"terminal target is an independently acquired service observation under the same contract");
            check(!terminal.getBoolean("goal_independently_verified"),"host controlled sequence is not phone semantic goal proof");
        }});
        test("same_user_button_task_pending_to_terminal_entire_contract_chain",()->{try(QualificationScopeHostTest.Env e=env()){
            ScriptModel model=new ScriptModel(e,"sequence");e.service.testInference=model;e.service.effectHook=()->e.service.prepare(CLOCK);
            LocalModelEngine engine=new LocalModelEngine(Paths.get(e.pm.packages.get("org.trillionnium.hepta.local").applicationInfo.sourceDir).toFile(),e.runtime);
            LocalTaskSession tasks=new LocalTaskSession(e.service,engine);ScopeUiFixture ui=new ScopeUiFixture(tasks,engine);TaskAuthorization expected=TaskAuthorization.parse(CLOCK_OWNER);
            ui.intent(new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER).putExtra("task",CLOCK_OWNER));Handler.hold=true;check(ui.start(),"actual ordinary Start reservation");
            byte[] pendingBytes=Files.readAllBytes(e.dir.resolve("control-session.json"));Files.write(e.dir.resolve("host-pending-before-start.json"),pendingBytes);JSONObject pending=new JSONObject(new String(pendingBytes,StandardCharsets.UTF_8));
            check("pending".equals(pending.getString("status"))&&"user_button".equals(pending.getString("origin"))&&pending.isNull("task_id")&&model.calls==0,"durable pending precedes controller/inference");
            check(expected.instructionSha256.equals(pending.getString("instruction_sha256"))&&expected.sha256.equals(pending.getString("task_authorization_sha256")),"pending binds exact original owner and contract");
            Handler.drain();long deadline=System.currentTimeMillis()+10000;JSONObject session=null;
            while(System.currentTimeMillis()<deadline){
                try{JSONObject current=json(e.dir.resolve("control-session.json"));if(tasks.lastResult!=null&&"model_reported_done".equals(current.getString("status"))){session=current;break;}}
                catch(Exception incompleteFakeAtomicWrite){/* synthetic AtomicFile has no platform atomic rename */}
                Thread.sleep(1);
            }
            LocalTaskController.TaskResult r=tasks.lastResult;check(r!=null&&session!=null,"same user-button task reaches actual terminal session write");controllerIdentity(r,model);
            check(model.calls==3&&e.service.opens==1&&r.cleanupKnown&&r.modelReportedSuccess&&session.getBoolean("cleanup_known")&&!session.getBoolean("pending")&&!session.getBoolean("running"),"single actual controlled chain completed cleanly");
            check(r.taskId.equals(session.getString("task_id"))&&"user_button".equals(session.getString("origin"))&&session.isNull("debug_nonce_sha256"),"ordinary source survives without debug nonce");
            check(expected.sha256.equals(session.getString("task_authorization_sha256"))&&expected.instructionSha256.equals(session.getString("instruction_sha256")),"pending and terminal session retain exact same contract/owner");
            Path directory=r.evidenceDirectory.toPath();JSONObject owner=json(directory.resolve("owner.json")),terminal=json(directory.resolve("result.json"));
            check(CLOCK_OWNER.equals(owner.getString("instruction"))&&expected.instructionSha256.equals(owner.getString("instruction_utf8_sha256")),"actual OWNER original UTF-8 bytes preserved");
            for(int step=1;step<=3;step++){
                JSONObject action=json(directory.resolve(String.format(Locale.ROOT,"step-%02d-action.json",step))),nativeAnswer=json(directory.resolve(String.format(Locale.ROOT,"step-%02d-model-0.json",step)));
                JSONObject authorization=action.getJSONObject("task_authorization"),last=authorization.getJSONObject("last_check");String run=nativeAnswer.getString("run_id");
                check(expected.instructionSha256.equals(nativeAnswer.getString("original_instruction_sha256"))&&run.equals(action.getString("model_run_id"))&&run.equals(last.getString("model_run_id")),"actual model answer/action/check run and owner binding");
                check(expected.sha256.equals(action.getString("task_authorization_sha256"))&&expected.sha256.equals(authorization.getString("authorization_sha256"))&&r.taskId.equals(authorization.getString("task_id")),"same task/contract throughout action chain");
                check(last.getBoolean("allowed")&&authorization.getBoolean("callback_lease_current")&&!authorization.getBoolean("callback_cancelled"),"current noncancelled authorized callback");
            }
            JSONObject gate=terminal.getJSONObject("task_authorization");String id=gate.getString("opened_observation_id");JSONObject observed=json(directory.resolve("scope-observation-"+id+".json"));
            check(CLOCK.equals(observed.getJSONObject("observation").getString("package"))&&r.taskId.equals(observed.getJSONObject("task_authorization").getString("task_id"))&&expected.sha256.equals(observed.getJSONObject("task_authorization").getString("authorization_sha256")),"same task target observation closes final method proof");
            check(expected.sha256.equals(gate.getString("authorization_sha256"))&&r.taskId.equals(gate.getString("task_id"))&&!terminal.getBoolean("goal_independently_verified"),"terminal contract retained without claiming real semantic goal proof");
        }});
        if(results.isEmpty())throw new IllegalArgumentException("unknown selected test case");
        int passed=0;for(JSONObject row:results)if("pass".equals(row.getString("status")))passed++;
        JSONObject result=new JSONObject().put("schema","hepta.owner-auth-independent-wiring-host.v1").put("passed",passed).put("failed",results.size()-passed).put("cases",new JSONArray(results)).put("phone_actions",0).put("native_inference",false).put("recreated_test_source",true);
        Files.write(output.resolve("RESULT.json"),(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));System.out.println(result.toString());if(passed!=results.size())System.exit(1);
    }
}
