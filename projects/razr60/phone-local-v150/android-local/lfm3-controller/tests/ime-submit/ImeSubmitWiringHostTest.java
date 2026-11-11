package org.trillionnium.hepta.local;

import android.os.Handler;
import android.view.accessibility.AccessibilityNodeInfo;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.*;

/** Executes extracted production gates/dispatch and full controller. Android effects are explicit fakes. */
public final class ImeSubmitWiringHostTest {
    static final String RUN="dddddddddddddddddddddddddddddddd";
    static final List<String> passed=new ArrayList<String>();
    interface Case{void run()throws Exception;}
    static void check(boolean value,String why){if(!value)throw new AssertionError(why);}
    static void test(String name,Case body)throws Exception{body.run();passed.add(name);System.out.println("PASS "+name);}
    static final class Setup implements AutoCloseable {
        final QualificationScopeHostTest.Env env;
        final HeptaAccessibilityService service;
        final TaskAuthorization.Gate authorization;
        final SubmitAttemptGuard ledger;
        final List<Map<String,Object>> journals=new ArrayList<Map<String,Object>>();
        Runnable journalHook;
        BackgroundSession background;
        Setup(String owner)throws Exception{
            env=new QualificationScopeHostTest.Env(false);service=env.service;
            check(service.acquireTask(env.task,()->{}),"lease");
            env.bound=QualificationScopeConfig.capture(service,env.task,null,env.runtime);service.bindQualificationScope(env.task,env.bound);
            authorization=service.bindTaskAuthorization(env.task,TaskAuthorization.parse(owner));service.appCatalogue(env.task,owner);
            ledger=new SubmitAttemptGuard(env.task,attempt->{journals.add(attempt.journal());if(journalHook!=null)journalHook.run();});
            service.bindSubmitAttempts(env.task,ledger);
            service.node.text="耳机";service.node.imePresent=true;service.node.imeLabel="搜索";capture();
        }
        void capture(){service.observe(env.task,env.dir.toFile(),()->false,Long.MAX_VALUE,new HeptaAccessibilityService.ObservationCallback(){
            public void onObservation(PhoneObservation value){}public void onError(String error){throw new AssertionError(error);}});}
        ActionDecision action()throws Exception{return ActionDecision.parse(raw(service.current,"submit",null),ActionDecision.IME_ACTION_SCHEMA);}
        HeptaAccessibilityService.ActionOutcome run(ActionDecision action)throws Exception{
            final HeptaAccessibilityService.ActionOutcome[] reply=new HeptaAccessibilityService.ActionOutcome[1];
            enqueue(action,()->false,value->reply[0]=value);check(reply[0]!=null,"synchronous fake reply");return reply[0];
        }
        void enqueue(ActionDecision action,HeptaAccessibilityService.Cancellation cancel,HeptaAccessibilityService.ActionCallback callback){
            PhoneObservation observed=service.current;
            ObservedTargetLabels targets=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,observed.id,observed.packageName,
                    Collections.singletonMap("n0",ObservedTargetLabels.project(observed.nodes.get(0).label())));
            service.perform(env.task,observed,action,targets,authorization,RUN,cancel,callback);
        }
        void background(int display){
            background=BackgroundSession.fixture(env.task,display,Collections.singleton(service.root.pkg));
            service.bindBackgroundSession(env.task,background);service.root.window.display=display;service.node.window.display=display;capture();
        }
        public void close(){if(background!=null)background.close();env.close();}
    }
    static String raw(PhoneObservation observed,String action,String text)throws Exception{
        JSONObject row=new JSONObject().put("reason","只依据当前已观察字段推进查询").put("action",action)
                .put("observation_id",observed.id).put("package",observed.packageName);
        if("submit".equals(action)||"type".equals(action))row.put("node_label",ObservedTargetLabels.project(observed.nodes.get(0).label())).put("node_id","n0");
        if("type".equals(action))row.put("text",text);
        if("wait".equals(action))row.put("duration_ms",100);
        if("done".equals(action))row.put("status","partial").put("summary","工具通道已尝试，业务完成仍需实机验证");
        return row.toString();
    }
    static void zero(Setup s,HeptaAccessibilityService.ActionOutcome r){check(!r.accepted&&!r.dispatched&&s.service.effects()==0,"no platform effect");}
    static void proof(Setup s,HeptaAccessibilityService.ActionOutcome result,String status)throws Exception{
        JSONObject value=result.imeSubmit;check(value!=null,"explicit submit proof");
        check(value.getBoolean("attempt_consumed")&&!value.getBoolean("automatic_retry_allowed")&&!value.getBoolean("goal_independently_verified"),"attempt never proves business success or permits retry");
        check(status.equals(value.getString("result"))&&s.env.task.equals(value.getString("task_id"))&&RUN.equals(value.getString("model_run_id")),"exact attempt result/task/model");
        check(value.getString("input_text_sha256").equals(ObservedImeEnter.hash("耳机")),"complete actual input binding");
    }
    static void directCases()throws Exception{
        test("actual_dispatch_fixed_node_action_consumed_first",()->{try(Setup s=new Setup("查询商品。")){
            s.service.node.onAction=()->check(s.journals.size()==1&&!s.ledger.available(s.service.node.pkg,ObservedImeEnter.hash("耳机")),"journal and consumption precede Android call");
            HeptaAccessibilityService.ActionOutcome r=s.run(s.action());check(r.accepted&&r.dispatched&&s.service.effects()==1,"one accepted call");
            check(s.service.node.lastAction==AccessibilityNodeInfo.AccessibilityAction.ACTION_IME_ENTER.getId()&&s.service.node.lastBundle==null,"fixed action with no model arguments");proof(s,r,"accepted");
        }});
        test("v6_submit_retains_once_and_exact_node_binding",()->{try(Setup s=new Setup("查询商品。")){
            s.service.node.onAction=()->check(s.journals.size()==1&&!s.ledger.available(s.service.node.pkg,ObservedImeEnter.hash("耳机")),"v6 consumes before fixed node action");
            HeptaAccessibilityService.ActionOutcome r=s.run(ActionDecision.parse(raw(s.service.current,"submit",null),ActionDecision.FIXED_INTENT_ACTION_SCHEMA));
            check(r.accepted&&r.dispatched&&s.service.effects()==1&&s.service.node.lastAction==AccessibilityNodeInfo.AccessibilityAction.ACTION_IME_ENTER.getId(),"v6 uses exactly the observed IME action");proof(s,r,"accepted");
            s.capture();HeptaAccessibilityService.ActionOutcome repeated=s.run(ActionDecision.parse(raw(s.service.current,"submit",null),ActionDecision.FIXED_INTENT_ACTION_SCHEMA));
            check(!repeated.dispatched&&s.service.effects()==1&&s.journals.size()==1,"v6 cannot replay consumed content");
        }});
        for(String changed:new String[]{"permission","label","display","text"})test("v6_submit_retains_boundary_"+changed,()->{try(Setup s=new Setup("permission".equals(changed)?"只允许输入和结束。":"查询商品。")){
            if("label".equals(changed)){s.service.node.imeLabel="发送";s.capture();}
            ActionDecision action=ActionDecision.parse(raw(s.service.current,"submit",null),ActionDecision.FIXED_INTENT_ACTION_SCHEMA);
            if("display".equals(changed))s.service.node.window.display=9;
            if("text".equals(changed))s.service.node.text="不同的完整输入";
            zero(s,s.run(action));check(s.journals.isEmpty(),"v6 cannot bypass the existing owner/query/display/text binding");
        }});
        test("unknown_schema_cannot_reach_submit_dispatch",()->{try(Setup s=new Setup("查询商品。")){
            for(String schema:new String[]{ObservedTargetLabels.ACTION_SCHEMA,ObservedAppLabels.ACTION_SCHEMA,"hepta.observed-action-gbnf.v7-unknown"}){
                boolean rejected=false;try{ActionDecision.parse(raw(s.service.current,"submit",null),schema);}catch(ActionDecision.InvalidActionException expected){rejected=true;}
                check(rejected,"submit requires an explicitly supported schema");
            }
            check(s.service.effects()==0&&s.journals.isEmpty(),"rejected schemas cannot consume or invoke");
        }});
        for(String label:new String[]{"Enter","Go","Done","发送","付款","下单","",null})test("unverified_or_commit_label_"+String.valueOf(label),()->{try(Setup s=new Setup("查询商品。")){
            s.service.node.imeLabel=label;s.capture();check(!s.service.current.nodes.get(0).submitAvailable,"unsupported label absent from capability");zero(s,s.run(s.action()));check(s.journals.isEmpty(),"no attempt for unverified action");
        }});
        for(String property:new String[]{"focus","editable","password","enabled","visible","absent","unknown","null_text"})test("required_observed_fact_"+property,()->{try(Setup s=new Setup("查询商品。")){
            if("focus".equals(property))s.service.node.focused=false;
            if("editable".equals(property))s.service.node.editable=false;
            if("password".equals(property))s.service.node.password=true;
            if("enabled".equals(property))s.service.node.enabled=false;
            if("visible".equals(property))s.service.node.visible=false;
            if("absent".equals(property))s.service.node.imePresent=false;
            if("unknown".equals(property))s.service.node.actionListUnknown=true;
            if("null_text".equals(property))s.service.node.text=null;
            s.capture();zero(s,s.run(s.action()));check(s.journals.isEmpty(),"no attempt before all facts");
        }});
        test("malformed_complete_text_cannot_grant_or_refresh_submit",()->{try(Setup s=new Setup("查询商品。")){
            ActionDecision action=s.action();StringBuilder text=new StringBuilder();for(int i=0;i<110;i++)text.append('查');s.service.node.text=text+"\uD800";
            zero(s,s.run(action));check(s.journals.isEmpty(),"invalid full text after capture refuses before consume");
            s.capture();check(s.service.current.nodes.get(0).inputTextSha256==null&&!s.service.current.nodes.get(0).submitAvailable,"invalid complete input cannot acquire capability");
        }});
        test("type_permission_does_not_authorize_submit",()->{try(Setup s=new Setup("只允许输入和结束。")){zero(s,s.run(s.action()));check(s.journals.isEmpty(),"owner boundary before effect");}});
        test("changed_label_and_full_text_are_stale",()->{
            try(Setup s=new Setup("查询商品。")){ActionDecision action=s.action();s.service.node.imeLabel="查询";zero(s,s.run(action));check(s.journals.isEmpty(),"changed actual label refused before consume");}
            try(Setup s=new Setup("查询商品。")){StringBuilder text=new StringBuilder();for(int i=0;i<110;i++)text.append('查');s.service.node.text=text+"A";s.capture();ActionDecision action=s.action();s.service.node.text=text+"B";zero(s,s.run(action));check(s.journals.isEmpty(),"change beyond prompt prefix refused");}
        });
        test("node_window_display_type_bound_before_consume",()->{for(String changed:new String[]{"window","display","type"})try(Setup s=new Setup("查询商品。")){
            if("window".equals(changed))s.service.node.window.id=8;if("display".equals(changed))s.service.node.window.display=9;if("type".equals(changed))s.service.node.window.type=2;
            zero(s,s.run(s.action()));check(s.journals.isEmpty(),"window/display/application gate precedes consume");
        }});
        test("journal_delay_rechecks_active_window_and_keeps_consumption",()->{try(Setup s=new Setup("查询商品。")){
            s.journalHook=()->s.service.root.pkg="com.example.other";HeptaAccessibilityService.ActionOutcome r=s.run(s.action());zero(s,r);
            check(s.journals.size()==1&&r.imeSubmit!=null&&"not_dispatched".equals(r.imeSubmit.getString("result")),"journal followed by changed root records no call");
            check(!s.ledger.available(QualificationScopeHostTest.SETTINGS,ObservedImeEnter.hash("耳机")),"no retry after reserved attempt");
        }});
        test("false_api_result_is_attempted_and_never_retried",()->{try(Setup s=new Setup("查询商品。")){
            s.service.node.actionResult=false;HeptaAccessibilityService.ActionOutcome r=s.run(s.action());check(!r.accepted&&r.dispatched&&s.service.effects()==1,"false return is an actual attempt");proof(s,r,"refused");
            s.capture();check(!s.service.current.nodes.get(0).submitAvailable,"false cannot re-arm");HeptaAccessibilityService.ActionOutcome repeated=s.run(s.action());check(!repeated.dispatched&&s.service.effects()==1,"no second platform call");
        }});
        test("exception_after_entering_is_unknown_not_clean_failure",()->{try(Setup s=new Setup("查询商品。")){
            s.service.node.actionThrows=true;HeptaAccessibilityService.ActionOutcome r=s.run(s.action());check(!r.accepted&&r.dispatched&&s.service.effects()==1,"post-call exception retains possible dispatch");proof(s,r,"unknown");check(r.imeSubmit.isNull("api_accepted"),"unknown API result remains null");
        }});
        test("cancelled_callback_keeps_submit_receipt",()->{try(Setup s=new Setup("查询商品。")){
            AtomicBoolean cancel=new AtomicBoolean();HeptaAccessibilityService.ActionOutcome[] box=new HeptaAccessibilityService.ActionOutcome[1];Handler.hold=true;
            s.enqueue(s.action(),cancel::get,r->box[0]=r);check(box[0]==null&&s.service.effects()==1,"effect before delayed callback");cancel.set(true);Handler.drain();
            check(!box[0].accepted&&box[0].dispatched,"cancellation cannot erase dispatch");proof(s,box[0],"accepted");
        }});
        test("retired_callback_keeps_old_submit_identity",()->{try(Setup s=new Setup("查询商品。")){
            HeptaAccessibilityService.ActionOutcome[] box=new HeptaAccessibilityService.ActionOutcome[1];Handler.hold=true;s.enqueue(s.action(),()->false,r->box[0]=r);
            s.service.releaseTask(s.env.task);Handler.drain();check(!box[0].accepted&&box[0].dispatched,"retired callback retains known dispatch");proof(s,box[0],"accepted");
        }});
        test("wait_and_node_renumber_cannot_repeat_same_input",()->{try(Setup s=new Setup("查询商品。")){
            s.run(s.action());s.capture();s.run(ActionDecision.parse(raw(s.service.current,"wait",null),ActionDecision.IME_ACTION_SCHEMA));s.capture();
            check(!s.service.current.nodes.get(0).submitAvailable,"fresh observation after wait still blocks same content");HeptaAccessibilityService.ActionOutcome r=s.run(s.action());check(!r.dispatched&&s.service.effects()==1,"no second submit");
        }});
        test("type_newline_does_not_implicitly_submit",()->{try(Setup s=new Setup("输入查询词。")){
            HeptaAccessibilityService.ActionOutcome r=s.run(ActionDecision.parse(raw(s.service.current,"type","耳机\n蓝牙"),ActionDecision.IME_ACTION_SCHEMA));
            check(r.accepted&&s.service.node.lastAction==AccessibilityNodeInfo.ACTION_SET_TEXT&&s.service.node.text.equals("耳机\n蓝牙")&&s.journals.isEmpty(),"SET_TEXT only, exact newline");
        }});
        test("background_node_gate_accepts_owned_display_only",()->{try(Setup s=new Setup("查询商品。")){
            s.background(9);HeptaAccessibilityService.ActionOutcome r=s.run(s.action());check(r.accepted&&r.dispatched&&r.imeSubmit.getInt("display_id")==9,"owned fake display preserved");
            check(r.imeSubmit.getString("background_generation").equals(s.background.generation),"same background generation");
            check(s.service.navigations==0&&s.service.gestures==0&&s.service.opens==0,"no global/navigation fallback");
        }});
        test("background_moved_node_to_display_zero_refused",()->{try(Setup s=new Setup("查询商品。")){
            s.background(9);s.service.node.window.display=0;zero(s,s.run(s.action()));check(s.journals.isEmpty(),"background ownership refuses before consume");
        }});
        test("background_closed_generation_refused",()->{try(Setup s=new Setup("查询商品。")){
            s.background(9);s.background.close();zero(s,s.run(s.action()));check(s.journals.isEmpty(),"retired display no fallback");
        }});
    }
    static void controllerCase(String syncFailure)throws Exception{
        try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            e.service.node.imePresent=true;e.service.node.imeLabel="搜索";
            final int[] calls={0};final List<String> prompts=new ArrayList<String>();
            LocalInference model=new LocalInference(){
                public LocalRuntimeConfig configuration(){return e.runtime;}
                public Handle generate(String prompt,String system,File image,DecisionGrammar grammar,int tokens,long timeout,Callback callback){
                    try{
                        int step=++calls[0];prompts.add(prompt);check(ActionDecision.FIXED_INTENT_ACTION_SCHEMA.equals(grammar.schema),"normal controller uses explicit v6 with retained IME binding");
                        if(step==2)check(grammar.allowsSubmit("n0"),"after type current field has submit");
                        if(step==2&&"callback".equals(syncFailure))Handler.hold=true;
                        else if(step==2&&syncFailure!=null){
                            Path task=e.dir.resolve("control-tasks").resolve(e.controller.currentTaskId());
                            android.system.Os.failFsyncPath=("file".equals(syncFailure)?task.resolve("ime-submit-01-attempt.json"):task).toString();
                        }
                        if(step>=3)check(!grammar.allowsSubmit("n0"),"after actual attempt grammar removes identical input across wait");
                        String action=step==1?"type":step==2?"submit":step==3?"wait":"done";
                        callback.onSuccess(raw(e.service.current,action,"耳机"),String.format(Locale.ROOT,"%032x",step));
                    }catch(Exception error){throw new IllegalStateException(error);}return ()->{};
                }
            };
            e.controller=new LocalTaskController(e.service,model);CountDownLatch done=new CountDownLatch(1);LocalTaskController.TaskResult[] result=new LocalTaskController.TaskResult[1];
            check(e.controller.start("查询当前应用的耳机。",new LocalTaskController.Listener(){public void onState(String state){}public void onFinished(LocalTaskController.TaskResult r){result[0]=r;done.countDown();}}),"normal user task starts");
            check(done.await(12,TimeUnit.SECONDS),"controller completes");
            if("callback".equals(syncFailure)){
                check("blocked".equals(result[0].status)&&!result[0].cleanupKnown&&calls[0]==2&&e.service.node.actions==2,
                        "lost callback blocks the task after exactly one IME attempt");
                Path dir=result[0].evidenceDirectory.toPath();
                check(Files.isRegularFile(dir.resolve("ime-submit-01-attempt.json"))&&!Files.exists(dir.resolve("step-02-action.json")),
                        "pre-call journal survives missing normal step receipt");
                JSONObject finalResult=new JSONObject(new String(Files.readAllBytes(dir.resolve("result.json")),StandardCharsets.UTF_8));
                check(finalResult.getJSONArray("submit_attempts").length()==1,"callback timeout retains full ledger independently");
                check(!e.controller.start("再次查询。",new LocalTaskController.Listener(){public void onState(String state){}public void onFinished(LocalTaskController.TaskResult r){}}),
                        "unknown callback outcome cannot automatically start another task");
                return;
            }
            if(syncFailure!=null){
                check("failed".equals(result[0].status)&&calls[0]==2&&e.service.node.actions==1
                        &&e.service.node.lastAction==AccessibilityNodeInfo.ACTION_SET_TEXT,"file/directory fsync failure prevents IME call");
                JSONObject finalResult=new JSONObject(new String(Files.readAllBytes(result[0].evidenceDirectory.toPath().resolve("result.json")),StandardCharsets.UTF_8));
                JSONObject attempted=finalResult.getJSONArray("submit_attempts").getJSONObject(0);
                check("not_dispatched".equals(attempted.getString("result"))&&!attempted.getBoolean("dispatch_attempted")
                        &&attempted.getBoolean("attempt_consumed"),"failed journal still records consumed but not invoked");
                return;
            }
            check("partial".equals(result[0].status)&&calls[0]==4&&e.service.node.actions==2,"one SET_TEXT and one explicit IME action, then wait/done");
            Path dir=result[0].evidenceDirectory.toPath();JSONObject journal=new JSONObject(new String(Files.readAllBytes(dir.resolve("ime-submit-01-attempt.json")),StandardCharsets.UTF_8));
            check("consumed_before_call".equals(journal.getString("stage"))&&!journal.has("dispatch_attempted"),"actual controller durable pre-call journal");
            JSONObject receipt=new JSONObject(new String(Files.readAllBytes(dir.resolve("step-02-action.json")),StandardCharsets.UTF_8));
            JSONObject proof=receipt.getJSONObject("ime_submit");check(proof.getString("attempt_id").equals(journal.getString("attempt_id")),"actual callback bound to journal");
            JSONObject finalResult=new JSONObject(new String(Files.readAllBytes(dir.resolve("result.json")),StandardCharsets.UTF_8));
            check(finalResult.getJSONArray("submit_attempts").length()==1,"final result retains attempts independently of step callbacks");
            check(prompts.get(2).contains("submit_attempt_consumed")&&prompts.get(2).contains("submit_input_sha256"),"real subsequent prompt retains submit history");
            String task=dir.toString(),file=dir.resolve("ime-submit-01-attempt.json").toString();
            check(android.system.Os.syncLog.indexOf(file)>=0&&android.system.Os.syncLog.indexOf(task)>android.system.Os.syncLog.indexOf(file)
                    &&android.system.Os.syncLog.contains(dir.getParent().toString())&&android.system.Os.syncLog.contains(e.dir.toString()),"production path requests file and all new parent-entry fsyncs");
        }finally{android.system.Os.failFsyncPath=null;}
    }
    public static void main(String[] args)throws Exception{
        Path output=Paths.get(args[0]);Files.createDirectories(output);QualificationScopeHostTest.output=output;
        directCases();test("normal_controller_type_submit_wait_with_durable_evidence",()->controllerCase(null));
        test("controller_file_fsync_failure_prevents_submit",()->controllerCase("file"));
        test("controller_directory_fsync_failure_prevents_submit",()->controllerCase("directory"));
        test("controller_callback_timeout_retains_attempt_without_replay",()->controllerCase("callback"));
        JSONObject result=new JSONObject().put("passed",passed.size()).put("failed",0).put("cases",new JSONArray(passed))
                .put("production_dispatch_executed",true).put("android_io_fake",true).put("real_virtual_display_tested",false).put("phone_tested",false);
        Files.write(output.resolve("RESULT.json"),result.toString(2).getBytes(StandardCharsets.UTF_8));
        System.out.println(result.toString());
    }
}
