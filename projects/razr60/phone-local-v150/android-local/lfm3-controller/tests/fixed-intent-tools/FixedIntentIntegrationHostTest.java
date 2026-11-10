package org.trillionnium.hepta.local;

import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.ResolveInfo;
import android.os.Handler;
import org.json.JSONObject;
import org.trillionnium.hepta.background.FixedIntentDispatch;
import org.trillionnium.hepta.background.FixedIntentTarget;
import org.trillionnium.hepta.background.FixedIntentTools;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Actual parser/grammar/controller/service/Android adapter; Android and inference are explicit IO fakes. */
public final class FixedIntentIntegrationHostTest {
    static final String RUN="dddddddddddddddddddddddddddddddd";
    static final String OWNER="请帮我写一条备忘录，下午三点取快递；保存后重新打开核对。";
    static final List<String> passed=new ArrayList<String>();
    interface Case{void run()throws Exception;}
    static void check(boolean value,String why){if(!value)throw new AssertionError(why);}
    static void test(String name,Case run)throws Exception{run.run();passed.add(name);}
    static void rejects(Case run)throws Exception{try{run.run();}catch(Exception expected){return;}throw new AssertionError("expected refusal");}
    static QualificationScopeHostTest.Env env()throws Exception{
        QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false);
        install(e,"notes.create",10382);install(e,"web.search",10384);return e;
    }
    static ActivityInfo install(QualificationScopeHostTest.Env e,String tool,int uid){
        FixedIntentTools.Profile p=FixedIntentTools.forAction(tool);ActivityInfo activity=new ActivityInfo();
        activity.packageName=p.packageName;activity.name=p.className;activity.applicationInfo=new ApplicationInfo();
        activity.applicationInfo.packageName=p.packageName;activity.applicationInfo.uid=uid;
        e.pm.activities.put(p.packageName+"/"+p.className,activity);
        ResolveInfo resolve=new ResolveInfo();resolve.activityInfo=activity;
        e.pm.intentResolvers.put(p.intentAction+"|"+p.mimeType,Collections.singletonList(resolve));
        e.service.launchable.put(p.packageName,p.packageName);return activity;
    }
    static FixedIntentAttemptGuard bind(QualificationScopeHostTest.Env e,String owner,FixedIntentAttemptGuard.Journal journal)throws Exception{
        check(e.service.acquireTask(e.task,()->{}),"task lease");
        e.bound=QualificationScopeConfig.capture(e.service,e.task,null,e.runtime);e.bound.requireReady();e.service.bindQualificationScope(e.task,e.bound);
        e.service.bindTaskAuthorization(e.task,TaskAuthorization.parse(owner));
        FixedIntentAttemptGuard guard=new FixedIntentAttemptGuard(e.task,journal);e.service.bindFixedIntentAttempts(e.task,guard);return guard;
    }
    static String raw(String obs,String action,String label,String pkg,String payload)throws Exception{
        return new JSONObject().put("reason","根据用户要求打开固定本地入口").put("action",action).put("observation_id",obs)
                .put("app_label",label).put("package",pkg).put("notes.create".equals(action)?"text":"query",payload).toString();
    }
    static ActionDecision decision(QualificationScopeHostTest.Env e,String action,String payload)throws Exception{
        FixedIntentTarget target=FixedIntentDispatch.inspect(e.service,android.os.Process.myUid(),action);
        return ActionDecision.parse(raw(e.service.current.id,action,ObservedAppLabels.project(target.appLabel),target.packageName,payload),ActionDecision.FIXED_INTENT_ACTION_SCHEMA);
    }
    static HeptaAccessibilityService.ActionOutcome perform(QualificationScopeHostTest.Env e,ActionDecision action,FixedIntentTarget target,String run,HeptaAccessibilityService.Cancellation cancel){
        HeptaAccessibilityService.ActionOutcome[] reply=new HeptaAccessibilityService.ActionOutcome[1];
        ObservedTargetLabels labels=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,e.service.current.id,e.service.current.packageName,Collections.singletonMap("n0",e.service.node.text));
        e.service.perform(e.task,e.service.current,action,labels,target,e.service.taskAuthorization,run,cancel,value->reply[0]=value);
        return reply[0];
    }
    static JSONObject json(Path file)throws Exception{return new JSONObject(new String(Files.readAllBytes(file),StandardCharsets.UTF_8));}
    static DecisionGrammar grammar(QualificationScopeHostTest.Env e,Map<String,FixedIntentTarget> targets){
        return DecisionGrammar.createFixedIntentAuthorized(e.service.current.id,e.service.current.packageName,Collections.<String>emptySet(),
                Collections.<String>emptySet(),Collections.<String>emptySet(),Collections.<String,ObservedScrollActions>emptyMap(),Collections.<String,ObservedImeEnter>emptyMap(),
                ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,e.service.current.id,e.service.current.packageName,Collections.<String,String>emptyMap()),
                ObservedAppLabels.create(ObservedAppLabels.SCHEMA,e.service.current.id,e.service.current.packageName,Collections.<String,String>emptyMap()),
                e.service.taskAuthorization.frame(),false,targets);
    }
    static final class ScriptModel implements LocalInference{
        final QualificationScopeHostTest.Env e;final boolean repair;int calls;
        final String body="来自合成模型的原文：下午三点取快递🙂\n<untrusted>";
        final List<String> prompts=new ArrayList<String>();
        ScriptModel(QualificationScopeHostTest.Env e,boolean repair){this.e=e;this.repair=repair;}
        public LocalRuntimeConfig configuration(){return e.runtime;}
        public Handle generate(String prompt,String system,File image,DecisionGrammar grammar,int maximum,long timeout,Callback callback){
            calls++;prompts.add(prompt);
            try{
                check(prompt.endsWith("\nOWNER\n"+OWNER),"natural Chinese owner preserved, no host preselected tool/body");
                int dispatchCall=repair?2:1;
                if(calls<=dispatchCall){
                    check(grammar.actions.contains("notes.create")&&ActionDecision.FIXED_INTENT_ACTION_SCHEMA.equals(grammar.schema),"actual local model receives native grammar branch");
                    FixedIntentTarget target=grammar.fixedIntentTargets.get("notes.create");
                    String answer=raw(grammar.observationId,target.action,ObservedAppLabels.project(target.appLabel),target.packageName,body);
                    if(repair&&calls==1)answer=answer.substring(0,answer.length()-1)+",\"arbitrary_extra\":\"forbidden\"}";
                    callback.onSuccess(answer,String.format(java.util.Locale.ROOT,"%032x",calls));
                }else{
                    check(!grammar.actions.contains("notes.create"),"consumed intent removed from actual next native grammar");
                    callback.onSuccess(new JSONObject().put("reason","编辑入口请求不等于已经保存").put("action","done")
                            .put("observation_id",grammar.observationId).put("package",grammar.currentPackage)
                            .put("status","partial").put("summary","合成边界：没有保存和重开证据").toString(),String.format(java.util.Locale.ROOT,"%032x",calls));
                }
            }catch(Exception failure){throw new IllegalStateException(failure);}
            return ()->{};
        }
    }
    static void actualController(boolean repair)throws Exception{
        try(QualificationScopeHostTest.Env e=env()){
            ScriptModel model=new ScriptModel(e,repair);e.controller=new LocalTaskController(e.service,model);
            LocalTaskController.TaskResult[] result=new LocalTaskController.TaskResult[1];CountDownLatch done=new CountDownLatch(1);
            check(e.controller.start(OWNER,null,new LocalTaskController.Listener(){public void onState(String value){}public void onFinished(LocalTaskController.TaskResult value){result[0]=value;done.countDown();}}),"ordinary controller start");
            check(done.await(10,TimeUnit.SECONDS),"controller callback");
            check("partial".equals(result[0].status)&&!result[0].modelReportedSuccess&&result[0].cleanupKnown,"launch never becomes task success");
            check(e.service.opens==1&&e.service.node.actions==0&&model.body.equals(e.service.lastStartedIntent.getStringExtra("android.intent.extra.TEXT")),"only actual model body dispatched once, no host extraction/type");
            Path evidence=result[0].evidenceDirectory.toPath();JSONObject receipt=json(evidence.resolve("step-01-action.json"));
            String run=String.format(java.util.Locale.ROOT,"%032x",repair?2:1);
            check(run.equals(receipt.getString("model_run_id"))&&run.equals(receipt.getJSONObject("fixed_intent").getString("model_run_id")),"actual final model/repair receipt bound");
            check(model.body.equals(receipt.getJSONObject("action").getString("text")),"serialized action exactly matches model output");
            check(!receipt.getJSONObject("fixed_intent").getBoolean("saved_or_search_results_verified"),"no saved claim");
            check(Files.exists(evidence.resolve("fixed-intent-01-attempt.json")),"durable pre-call journal");
            String second=model.prompts.get(model.prompts.size()-1);
            check(second.contains("fixed_intent_payload")&&second.contains("\\u003cuntrusted>"),"prior dispatched body retained as escaped untrusted data");
        }
    }
    public static void main(String[] args)throws Exception{
        Path out=Paths.get(args[0]);Files.createDirectories(out);QualificationScopeHostTest.output=out;
        test("natural_chinese_owner_reaches_local_model_tool_choice",()->actualController(false));
        test("format_repair_uses_latest_actual_model_run_binding",()->actualController(true));
        test("legacy_schemas_do_not_admit_fixed_intents",()->{try(QualificationScopeHostTest.Env e=env()){
            String value=raw(e.service.current.id,"notes.create","com.motorola.stylus","com.motorola.stylus","正文");
            for(String schema:new String[]{ObservedTargetLabels.ACTION_SCHEMA,ObservedAppLabels.ACTION_SCHEMA,ActionDecision.IME_ACTION_SCHEMA})rejects(()->ActionDecision.parse(value,schema));
        }});
        for(String tool:new String[]{"notes.create","web.search"})test("fixed_dispatch_exact_contract_"+tool,()->{try(QualificationScopeHostTest.Env e=env()){
            List<Map<String,Object>> journal=new ArrayList<Map<String,Object>>();FixedIntentAttemptGuard guard=bind(e,"继续完成任务。",a->journal.add(a.journal()));
            FixedIntentTarget target=FixedIntentDispatch.inspect(e.service,android.os.Process.myUid(),tool);String payload="双引号\" 换行\n中文🙂";
            e.service.effectHook=()->check(journal.size()==1&&!guard.available(tool),"journal/consumption precede actual API");
            HeptaAccessibilityService.ActionOutcome r=perform(e,decision(e,tool,payload),target,RUN,()->false);Intent intent=e.service.lastStartedIntent;FixedIntentTools.Profile profile=FixedIntentTools.forAction(tool);
            check(r.accepted&&r.dispatched&&e.service.opens==1&&r.fixedIntent!=null,"one actual Android call and receipt");
            check(profile.intentAction.equals(intent.getAction())&&(profile.mimeType==null?intent.getType()==null:profile.mimeType.equals(intent.getType()))
                    &&(profile.packageName+"/"+profile.className).equals(intent.getComponent().flattenToString())&&intent.extraCount()==1
                    &&payload.equals(intent.getStringExtra(profile.extraName)),"only exact component/action/type/extra and full payload");
            check("launch_accepted".equals(r.fixedIntent.getString("result"))&&!r.fixedIntent.getBoolean("goal_independently_verified"),"no success on launch");
            HeptaAccessibilityService.ActionOutcome repeated=perform(e,decision(e,tool,"different body"),target,RUN,()->false);
            check(!repeated.accepted&&!repeated.dispatched&&e.service.opens==1,"new payload does not re-arm tool");
        }});
        test("exact_target_uid_changed_before_call_rejected",()->{try(QualificationScopeHostTest.Env e=env()){
            bind(e,OWNER,a->{});FixedIntentTarget target=FixedIntentDispatch.inspect(e.service,android.os.Process.myUid(),"notes.create");ActionDecision action=decision(e,"notes.create","正文");
            e.pm.activities.get(target.packageName+"/"+target.className).applicationInfo.uid++;
            HeptaAccessibilityService.ActionOutcome result=perform(e,action,target,RUN,()->false);check(!result.accepted&&!result.dispatched&&e.service.effects()==0,"UID mismatch must not dispatch");
        }});
        test("ordinary_app_permission_not_bypassed_by_fixed_target",()->{try(QualificationScopeHostTest.Env e=env()){
            ActivityInfo info=install(e,"notes.create",10382);info.permission="synthetic.permission.PROTECTED";e.service.fixedPermissionGranted=false;
            rejects(()->FixedIntentDispatch.inspect(e.service,android.os.Process.myUid(),"notes.create"));
            check(e.service.permissionCheckedUid==android.os.Process.myUid(),"checked actual ordinary app UID");
            rejects(()->FixedIntentDispatch.inspect(e.service,0,"notes.create"));rejects(()->FixedIntentDispatch.inspect(e.service,2000,"notes.create"));
        }});
        for(String denied:new String[]{"exported","enabled","app_enabled","filter"})test("unavailable_target_"+denied,()->{try(QualificationScopeHostTest.Env e=env()){
            ActivityInfo info=install(e,"notes.create",10382);if("exported".equals(denied))info.exported=false;else if("enabled".equals(denied))info.enabled=false;else if("app_enabled".equals(denied))info.applicationInfo.enabled=false;else e.pm.intentResolvers.clear();
            rejects(()->FixedIntentDispatch.inspect(e.service,android.os.Process.myUid(),"notes.create"));
        }});
        test("journal_failure_consumes_without_dispatch",()->{try(QualificationScopeHostTest.Env e=env()){
            FixedIntentAttemptGuard guard=bind(e,OWNER,a->{throw new java.io.IOException("synthetic fsync failure");});FixedIntentTarget target=FixedIntentDispatch.inspect(e.service,android.os.Process.myUid(),"notes.create");
            HeptaAccessibilityService.ActionOutcome result=perform(e,decision(e,"notes.create","正文"),target,RUN,()->false);
            check(!result.accepted&&!result.dispatched&&e.service.effects()==0&&!guard.available("notes.create"),"failed durable write cannot act or re-arm");
        }});
        test("cancel_after_journal_consumes_zero_dispatch",()->{try(QualificationScopeHostTest.Env e=env()){
            AtomicBoolean stop=new AtomicBoolean();FixedIntentAttemptGuard guard=bind(e,OWNER,a->stop.set(true));FixedIntentTarget target=FixedIntentDispatch.inspect(e.service,android.os.Process.myUid(),"notes.create");
            HeptaAccessibilityService.ActionOutcome result=perform(e,decision(e,"notes.create","正文"),target,RUN,stop::get);
            check(!result.accepted&&!result.dispatched&&!guard.available("notes.create")&&e.service.effects()==0,"cancel prevents effects without rearming");
        }});
        test("platform_exception_is_consumed_unknown_not_retry",()->{try(QualificationScopeHostTest.Env e=env()){
            FixedIntentAttemptGuard guard=bind(e,OWNER,a->{});FixedIntentTarget target=FixedIntentDispatch.inspect(e.service,android.os.Process.myUid(),"notes.create");
            e.service.effectHook=()->{throw new IllegalStateException("synthetic lost return after effect");};
            HeptaAccessibilityService.ActionOutcome result=perform(e,decision(e,"notes.create","正文"),target,RUN,()->false);
            check(!result.accepted&&result.dispatched&&"unknown".equals(result.fixedIntent.getString("result"))&&e.service.effects()==1&&!guard.available("notes.create"),"uncertain platform call preserves actual attempt");
        }});
        test("missing_native_run_or_target_cannot_dispatch",()->{try(QualificationScopeHostTest.Env e=env()){
            bind(e,OWNER,a->{});FixedIntentTarget target=FixedIntentDispatch.inspect(e.service,android.os.Process.myUid(),"notes.create");
            HeptaAccessibilityService.ActionOutcome result=perform(e,decision(e,"notes.create","正文"),target,"invalid",()->false);check(!result.accepted&&!result.dispatched&&e.service.effects()==0,"native run required");
        }});
        test("only_and_sequence_constraints_exclude_new_tools",()->{
            check(!TaskAuthorization.parse("只允许查找、打开和结束。").allows("notes.create"),"explicit only preserved");
            check(!TaskAuthorization.parse("先查找手机上安装的笔记应用，再打开它。").bind("cccccccccccccccccccccccccccccccc").frame().allows("notes.create"),"semantic tool cannot bypass find/open prerequisite");
            check(TaskAuthorization.parse("只允许创建笔记和结束。").summary().contains("打开本地笔记草稿"),"new tools present in permission summary");
        });
        test("actual_v6_grammar_emit_and_missing_target_policy",()->{try(QualificationScopeHostTest.Env e=env()){
            bind(e,OWNER,a->{});Map<String,FixedIntentTarget> targets=e.service.fixedIntentTargets(e.task,e.service.taskAuthorization.frame());DecisionGrammar grammar=grammar(e,targets);
            Files.write(out.resolve("fixed-intents.gbnf"),grammar.text.getBytes(StandardCharsets.UTF_8));
            ActionDecision action=decision(e,"notes.create","正文");
            ActionPolicy.validateAuthorizedDecision(action,e.service.current.packageName,Collections.<String>emptySet(),grammar.targets,grammar.appLabels,e.service.taskAuthorization,grammar.authorization,targets);
            rejects(()->ActionPolicy.validateAuthorizedDecision(action,e.service.current.packageName,Collections.<String>emptySet(),grammar.targets,grammar.appLabels,e.service.taskAuthorization,grammar.authorization));
            Files.write(out.resolve("grammar-inputs.json"),new JSONObject().put("observation_id",e.service.current.id).put("notes",raw(e.service.current.id,"notes.create","com.motorola.stylus","com.motorola.stylus","正文🙂"))
                    .put("web",raw(e.service.current.id,"web.search","com.zui.browser","com.zui.browser","北京 上海 机票" )).toString().getBytes(StandardCharsets.UTF_8));
        }});
        System.out.println(new JSONObject().put("passed",passed.size()).put("failed",0).put("cases",passed).put("android_runtime",false).put("native_inference",false).put("phone_operations",false));
    }
}
