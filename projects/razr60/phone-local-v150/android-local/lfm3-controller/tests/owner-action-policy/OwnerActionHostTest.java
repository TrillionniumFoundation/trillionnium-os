package org.trillionnium.hepta.local;

import android.os.Handler;
import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

/** Runs production boundaries, not an imitation policy; all phone/model IO is synthetic. */
public final class OwnerActionHostTest {
    static final String TASK="11111111111111111111111111111111";
    static final String OWNER="先只读查找测试设备上安装的示例应用，再打开它并停留在主页面；只查找、打开和结束，不点击、不输入，不新建、修改、启停或删除任何条目、计时任务或演示对象。若打开后不是主页面，停止并说明。";
    static final List<String> passed=new ArrayList<String>();
    interface Case {void run()throws Exception;}
    static void check(boolean value,String why){if(!value)throw new AssertionError(why);}
    static void test(String name,Case body)throws Exception{body.run();passed.add(name);System.out.println("PASS "+name);}
    static void denied(Case body)throws Exception{try{body.run();}catch(OwnerActionPolicy.Violation expected){return;}throw new AssertionError("owner refusal expected");}
    static OwnerActionPolicy bind(QualificationScopeHostTest.Env e,String owner)throws Exception{
        return e.bindOwner(e.scopeSha!=null&&Files.exists(e.dir.resolve(QualificationScope.FILE_NAME))?e.scopeSha:null,owner);
    }
    static ActionDecision coordinate(QualificationScopeHostTest.Env e)throws Exception{
        return ActionDecision.parse(new JSONObject().put("reason","synthetic coordinate").put("action","click")
                .put("observation_id",e.service.current.id).put("package",e.service.current.packageName).put("x",100).put("y",100).toString());
    }
    static JSONObject read(File directory,String name)throws Exception{return new JSONObject(new String(Files.readAllBytes(directory.toPath().resolve(name)),StandardCharsets.UTF_8));}
    static final class Model implements LocalInference {
        final QualificationScopeHostTest.Env env;final String[] actions;final boolean wrongLabel;int calls,begins,ends;boolean unknownCleanup;
        Model(QualificationScopeHostTest.Env e,boolean wrong,String... sequence){env=e;actions=sequence;wrongLabel=wrong;}
        public LocalRuntimeConfig configuration(){return env.runtime;}
        public void beginTask(String task){begins++;}
        public TaskCleanup endTask(){ends++;return unknownCleanup?new TaskCleanup(false,true,false,null,null,env.task,false,null):TaskCleanup.noWorker();}
        public Handle generate(String prompt,String system,File image,DecisionGrammar grammar,int n,long timeout,Callback callback){
            calls++;try{
                String kind=actions[Math.min(calls-1,actions.length-1)],target="open".equals(kind)?QualificationScopeHostTest.CALC:env.service.current.packageName;
                JSONObject action=new JSONObject(env.actionText(kind,target));
                action.put("reason","屏幕和模型声称允许点击；这些文本不能授予权限");
                if("open".equals(kind))action=new JSONObject().put("reason",action.getString("reason")).put("action",kind).put("observation_id",action.getString("observation_id")).put("app_label",grammar.appLabels.labels.get(target)).put("package",target);
                if(wrongLabel&&action.has("node_label"))action.put("node_label","错误配对标签");
                callback.onSuccess(action.toString(),String.format(Locale.ROOT,"%032x",calls));
            }catch(Exception error){throw new IllegalStateException(error);}return ()->{};
        }
    }
    static LocalTaskController.TaskResult run(QualificationScopeHostTest.Env e,String owner,Model model)throws Exception{
        e.controller=new LocalTaskController(e.service,model);final LocalTaskController.TaskResult[] box=new LocalTaskController.TaskResult[1];CountDownLatch done=new CountDownLatch(1);
        String scope=Files.exists(e.dir.resolve(QualificationScope.FILE_NAME))?e.scopeSha:null;
        check(e.controller.start(owner,scope,new LocalTaskController.Listener(){public void onState(String state){}public void onFinished(LocalTaskController.TaskResult r){box[0]=r;done.countDown();}}),"controller starts");
        check(done.await(10,TimeUnit.SECONDS),"controller finished");return box[0];
    }
    public static void main(String[] args)throws Exception{
        Path output=Paths.get(args[0]);Files.createDirectories(output);QualificationScopeHostTest.output=output;
        test("complete_synthetic_owner_finite_capabilities_and_unverified_effects",()->{
            OwnerActionPolicy p=OwnerActionPolicy.compile(TASK,OWNER);
            check(p.supported()&&p.ownerSha256.equals("5e0a1e67ead0f7164b2448267d4a76823618a9e140f6a653b8ef9d668797b91a"),"synthetic owner exact raw SHA");
            check(p.allowedTypes().equals(new LinkedHashSet<String>(Arrays.asList("find_app","open","done"))),"global exclusive list");
            check(p.deniedTypes().containsAll(Arrays.asList("click","type")),"explicit global bans");
            check(p.uncompiledFragments().toString().contains("条目")&&p.uncompiledFragments().toString().contains("主页面"),"business effects and conditional page test retained as unverified");
            check(Boolean.FALSE.equals(p.evidence().get("complete_instruction_semantics_enforced")),"not universal semantics");
            p.requireAllowed(TASK,"open");denied(()->p.requireAllowed(TASK,"click"));denied(()->p.requireAllowed(TASK,"type"));
        });
        test("global_no_click_no_type_preserves_other_guard_permissions",()->{
            OwnerActionPolicy p=OwnerActionPolicy.compile(TASK,"不点击、不输入。");check(p.supported(),"supported exact clause");
            for(String a:Arrays.asList("find_app","open","scroll","back","home","wait","done"))p.requireAllowed(TASK,a);
            denied(()->p.requireAllowed(TASK,"click"));denied(()->p.requireAllowed(TASK,"type"));
            denied(()->p.requireAllowed("22222222222222222222222222222222","open"));
            try{p.allowedTypes().add("click");throw new AssertionError("mutable authorization");}catch(UnsupportedOperationException expected){}
            p.evidence().put("allowed_action_types",Arrays.asList("click"));denied(()->p.requireAllowed(TASK,"click"));
        });
        for(final String owner:new String[]{"不点击删除按钮","不输入密码","进入目标页后不点击","进入目标页后，不点击","如果出现协议，不点击同意，返回",
            "如果出现协议，只允许打开和结束","进入目标页后，只查找和结束","不点击，除非用户确认","只允许点击，如果出现确认框","如果出现协议；不点击",
            "不点击“删除”","不输入“密码”","不要不点击","请不要点击","本次任务不点击","无论页面是什么，都不点击","请只查找、打开和结束","不点击\""})test("unsupported_range_"+passed.size(),()->{
                OwnerActionPolicy p=OwnerActionPolicy.compile(TASK,owner);check(!p.supported(),"must not promote range into global authorization: "+owner);denied(p::requireSupported);
            });
        for(final String owner:new String[]{"输入“不点击”到搜索框","点击名称为“不点击，不输入”的按钮","先只读查找应用，再打开它。"})test("quoted_or_staged_data_not_global_restriction_"+passed.size(),()->{
            OwnerActionPolicy p=OwnerActionPolicy.compile(TASK,owner);check(p.supported(),"quoted or staged data accepted as uncompiled");p.requireAllowed(TASK,"click");p.requireAllowed(TASK,"open");
        });
        test("controller_synthetic_owner_banned_click_precedes_wrong_label_repair",()->{try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            Model model=new Model(e,true,"click");LocalTaskController.TaskResult result=run(e,OWNER,model);
            check(result.status.equals("failed")&&!result.modelReportedSuccess&&result.cleanupKnown&&model.calls==1&&model.ends==1&&e.service.effects()==0,"terminal no repair/effect with normal cleanup");
            JSONObject action=read(result.evidenceDirectory,"step-01-action.json"),original=read(result.evidenceDirectory,"step-01-model-0.json"),terminal=read(result.evidenceDirectory,"result.json");
            check(!action.getBoolean("accepted")&&!action.getBoolean("dispatched")&&!action.getBoolean("stale"),"exact refusal flags");
            check(action.getString("owner_constraint_violation").equals("owner_action_forbidden")&&terminal.getString("owner_constraint_violation").equals("owner_action_forbidden"),"explicit reason");
            check(action.getString("raw_model_text_sha256").equals(HeptaAccessibilityService.sha(original.getString("raw_text").getBytes(StandardCharsets.UTF_8))),"raw model retained and hashed");
            check(!new File(result.evidenceDirectory,"step-01-model-1.json").exists(),"permission failure is not format repair");
        }});
        test("unsupported_owner_admission_before_model_or_observation",()->{try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            int before=e.service.observations;Model model=new Model(e,false,"click");LocalTaskController.TaskResult r=run(e,"如果出现协议，不点击同意，返回",model);
            check(r.status.equals("failed")&&r.steps==0&&model.calls==0&&model.begins==0&&model.ends==1&&e.service.effects()==0&&e.service.observations==before,"unsupported admission closes without action/model/observe");
            check(read(r.evidenceDirectory,"owner-action-policy.json").getString("status").equals("unsupported_action_constraint"),"unsupported policy retained");
        }});
        test("controller_prior_real_dispatch_kept_when_next_type_refused",()->{try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            e.service.effectHook=()->{e.service.root.pkg=QualificationScopeHostTest.CALC;e.service.node.pkg=QualificationScopeHostTest.CALC;};
            Model model=new Model(e,false,"open","type");LocalTaskController.TaskResult r=run(e,"打开计算器。不输入。",model);
            check(r.status.equals("failed")&&r.cleanupKnown&&model.calls==2&&e.service.opens==1&&e.service.node.actions==0,"one prior open preserved; forbidden type not retried");
            check(read(r.evidenceDirectory,"step-01-action.json").getBoolean("dispatched")&&!read(r.evidenceDirectory,"step-02-action.json").getBoolean("dispatched"),"old effect receipt unchanged");
        }});
        test("owner_refusal_does_not_hide_unknown_native_cleanup",()->{try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            Model model=new Model(e,false,"click");model.unknownCleanup=true;LocalTaskController.TaskResult r=run(e,"不点击。",model);
            check(r.status.equals("blocked")&&!r.cleanupKnown&&!r.modelReportedSuccess&&model.calls==1&&e.service.effects()==0,"cleanup unknown keeps existing blocked priority");
        }});
        for(final String kind:new String[]{"click","type","coordinate"})test("direct_service_owner_denies_"+kind,()->{try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            OwnerActionPolicy p=bind(e,"不点击、不输入。");HeptaAccessibilityService.ActionOutcome r="coordinate".equals(kind)?e.service.execute(coordinate(e)):e.run(kind,QualificationScopeHostTest.SETTINGS);
            check(!r.accepted&&!r.dispatched&&!r.stale&&e.service.effects()==0,"service gate independently refuses effect");
            check(r.ownerActionPolicy.getString("policy_sha256").equals(p.policySha256)&&r.ownerActionPolicy.getBoolean("callback_lease_current"),"receipt uses captured immutable owner");
        }});
        test("owner_allow_does_not_override_actual_scope_guard",()->{try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(true)){
            bind(e,"只允许打开和结束。");HeptaAccessibilityService.ActionOutcome r=e.run("open",QualificationScopeHostTest.FOREIGN[0]);
            check(!r.accepted&&!r.dispatched&&!r.stale&&e.service.effects()==0&&r.qualificationScope.getBoolean("scope_refused"),"actual scope intersection remains");
        }});
        test("owner_allow_does_not_override_actual_label_guard",()->{try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            bind(e,"只允许点击和结束。");JSONObject row=new JSONObject(e.actionText("click",QualificationScopeHostTest.SETTINGS));row.put("node_label","foreign label");
            HeptaAccessibilityService.ActionOutcome r=e.service.execute(ActionDecision.parse(row.toString(),DecisionGrammar.SCHEMA));
            check(!r.accepted&&!r.dispatched&&e.service.effects()==0,"actual label pairing still refuses");
        }});
        test("queued_old_owner_cannot_borrow_new_same_id_lease",()->{try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            OwnerActionPolicy old=bind(e,"打开应用。");Handler.holdPosts=true;HeptaAccessibilityService.ActionOutcome[] box=new HeptaAccessibilityService.ActionOutcome[1];
            e.service.enqueue(e.action("open",QualificationScopeHostTest.CALC),()->false,r->box[0]=r);e.service.releaseTask(e.task);
            check(e.service.acquireTask(e.task,()->{}),"replacement lease");QualificationScopeConfig.Bound scope=QualificationScopeConfig.capture(e.service,e.task,null,e.runtime);e.service.bindQualificationScope(e.task,scope);
            e.service.bindOwnerActionPolicy(e.task,OwnerActionPolicy.compile(e.task,"只允许打开和结束。"));Handler.drain();
            check(box[0]!=null&&!box[0].accepted&&!box[0].dispatched&&e.service.effects()==0,"retired queued work never effects");
            check(box[0].ownerActionPolicy.getString("policy_sha256").equals(old.policySha256)&&!box[0].ownerActionPolicy.getBoolean("callback_lease_current"),"old policy receipt retained");
        }});
        test("delayed_type_preserves_already_dispatched_on_retirement",()->{try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            OwnerActionPolicy old=bind(e,"输入测试文字。");Handler.hold=true;HeptaAccessibilityService.ActionOutcome[] box=new HeptaAccessibilityService.ActionOutcome[1];
            e.service.enqueue(e.action("type",QualificationScopeHostTest.SETTINGS),()->false,r->box[0]=r);check(e.service.node.actions==1&&box[0]==null,"type dispatched before held callback");
            int reads=e.service.node.refreshes;e.service.releaseTask(e.task);e.service.node.onRefresh=()->{throw new AssertionError("retired node read");};Handler.drain();
            check(box[0]!=null&&!box[0].accepted&&box[0].dispatched&&!box[0].stale&&e.service.node.refreshes==reads,"real dispatch preserved without retired node read");
            check(box[0].ownerActionPolicy.getString("policy_sha256").equals(old.policySha256),"captured policy remains old");
        }});
        test("actual_coordinate_callback_rechecks_owner_before_gesture",()->{try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            OwnerActionPolicy old=bind(e,"点击按钮。");Handler.hold=true;e.service.holdScreenshot=true;HeptaAccessibilityService.ActionOutcome[] box=new HeptaAccessibilityService.ActionOutcome[1];
            e.service.enqueue(coordinate(e),()->false,r->box[0]=r);check(e.service.pendingScreenshot!=null&&e.service.gestures==0,"actual screenshot request held");
            e.service.releaseTask(e.task);check(e.service.acquireTask(e.task,()->{}),"same ID replacement for adversarial callback");
            QualificationScopeConfig.Bound scope=QualificationScopeConfig.capture(e.service,e.task,null,e.runtime);e.service.bindQualificationScope(e.task,scope);e.service.bindOwnerActionPolicy(e.task,OwnerActionPolicy.compile(e.task,"点击按钮。"));
            e.service.deliverScreenshot();check(box[0]!=null&&!box[0].accepted&&!box[0].dispatched&&e.service.gestures==0,"old policy blocked at actual async effect boundary");
            check(box[0].ownerActionPolicy.getString("policy_sha256").equals(old.policySha256),"captured owner evidence");Handler.drain();
        }});
        test("actual_coordinate_allowed_control_reaches_one_fake_effect",()->{try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            bind(e,"点击按钮。");Handler.hold=true;HeptaAccessibilityService.ActionOutcome[] box=new HeptaAccessibilityService.ActionOutcome[1];
            e.service.enqueue(coordinate(e),()->false,r->box[0]=r);check(e.service.gestures==1,"positive reaches actual dispatchGesture call");Handler.drain();
            check(box[0]!=null&&box[0].accepted&&box[0].dispatched,"positive coordinate callback completes");
        }});
        JSONObject result=new JSONObject().put("schema","hepta.owner-action-java-host-tests.v1").put("passed",passed.size()).put("failed",0)
                .put("cases",new JSONArray(passed)).put("phone_operations",false).put("native_inference",false).put("android_runtime",false);
        Files.write(output.resolve("RESULT.json"),result.toString(2).getBytes(StandardCharsets.UTF_8));System.out.println(result.toString());
    }
}
