package org.trillionnium.hepta.local;

import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.graphics.Rect;
import org.json.JSONObject;
import org.trillionnium.hepta.background.FixedIntentTarget;
import org.trillionnium.hepta.background.FixedIntentTools;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Frame;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Node;

/** Real completion/controller classes; Android observation/effect and native inference are explicit IO fakes. */
public final class TaskCompletionGateHostTest {
    static final String TASK="11111111111111111111111111111111",P=NotesCompletionEvidence.NOTES;
    static final String BODY="明天下午三点取快递。",H="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static final String OWNER=owner(BODY),DRAFT_OWNER="新建笔记，正文为“"+BODY+"”，不要保存。",WEB="通过 web.search 网页查询商品信息，只允许网页查询、滚动、等待和结束。";
    static final List<String> passed=new ArrayList<String>();static Path output;static int observations;
    interface Case{void run()throws Exception;}
    static void test(String name,Case run)throws Exception{run.run();passed.add(name);System.out.println("PASS "+name);}
    static void check(boolean b,String why){if(!b)throw new AssertionError(why);}
    static String owner(String body){return "打开 Moto 笔记（com.motorola.stylus），新建一条笔记，正文完整写入以下一行："+body+" 保存这条新笔记，然后回到笔记列表，重新打开它并停留在正文完整可见的页面。不要修改或删除已有笔记，不分享或发送。";}
    static String id(int n){return String.format(Locale.ROOT,"%032x",n);}
    static Node n(String id,String pkg,String text,String view,int[] bounds,boolean editable,boolean click,boolean scroll){return new Node(id,pkg,text,text,view,editable?ObservedImeEnter.hash(text):null,bounds,editable,click,scroll,true,false);}
    static Frame initial(){return new Frame(id(++observations),QualificationScopeHostTest.SETTINGS,7,0,null,1,true,false,Collections.<Node>emptyList());}
    static Frame editor(){return new Frame(id(++observations),P,7,0,null,1,true,false,Arrays.asList(n("n0",P,BODY,"",new int[]{10,100,600,500},true,true,false),n("n1",P,"NoteEditor","",new int[]{0,0,1000,2000},false,false,true)));}
    static Frame listing(){return new Frame(id(++observations),P,7,0,null,1,true,false,Arrays.asList(n("n0",P,BODY,"",new int[]{10,100,600,300},false,true,false),n("n1",P,"",P+":id/view_pager2",new int[]{0,80,1000,2000},false,false,true),n("n2",P,"所有笔记",P+":id/title_text",new int[]{0,0,300,80},false,false,false)));}
    static TaskCompletionGate gate(){TaskCompletionGate g=new TaskCompletionGate(TASK,OWNER,TaskAuthorization.parse(OWNER));g.bindInstalled(new NotesCompletionEvidence.Installed(P,10382,Collections.singletonMap("base",H)));return g;}
    static ActionDecision action(Frame f,String tool,String payload,String node)throws Exception{
        JSONObject o=new JSONObject().put("reason","根据本次真实观察选择一个工具").put("action",tool).put("observation_id",f.observationId);
        if(FixedIntentTools.isTool(tool)){FixedIntentTools.Profile p=FixedIntentTools.forAction(tool);o.put("app_label",p.packageName).put("package",p.packageName).put("notes.create".equals(tool)?"text":"query",payload);}
        else{o.put("package",f.packageName);if("click".equals(tool))o.put("node_label",ObservedTargetLabels.project(BODY)).put("node_id",node);if("done".equals(tool))o.put("status","success").put("summary","synthetic model claim only");}
        return ActionDecision.parse(o.toString(),ActionDecision.FIXED_INTENT_ACTION_SCHEMA);
    }
    static Map<String,Object> fixed(Frame before,ActionDecision a,String run)throws Exception{
        FixedIntentTarget t=new FixedIntentTarget(a.action,a.packageName,10382,null);FixedIntentAttemptGuard g=new FixedIntentAttemptGuard(TASK,v->{});
        FixedIntentAttemptGuard.Attempt p=g.consume(new FixedIntentAttemptGuard.Binding(TASK,run,before.observationId,before.packageName,before.windowId,before.displayId,before.backgroundGeneration,t,a.text));g.entering(p);return g.finished(p,true);
    }
    static Frame launched(TaskCompletionGate g)throws Exception{Frame b=initial(),a=editor();ActionDecision d=action(b,"notes.create",BODY,null);g.observed(b);g.action(1,id(1),d,true,true,false,b,a,fixed(b,d,id(1)));return a;}
    static void chain(TaskCompletionGate g,boolean wrongItem)throws Exception{Frame e=launched(g),l=listing(),r=editor();g.action(2,id(2),action(e,"back",null,null),true,true,false,e,l,null);g.action(3,id(3),action(l,"click",null,wrongItem?"n9":"n0"),true,true,false,l,r,null);check(g.verified(r)==!wrongItem,"only actual same observed item can prove reopen");}
    static void pureCases()throws Exception{
        test("owner_literal_contract_and_no_model_chosen_goal",()->{
            TaskCompletionGate g=gate();check(TaskCompletionGate.NOTES.equals(g.contract.kind)&&BODY.equals(g.contract.body),"literal owner parsed without model body generation");
            for(String s:Arrays.asList("不要"+OWNER,OWNER+"再查询机票。","读出当前页面。",OWNER.replace("保存这条新笔记","不要保存这条新笔记"))){TaskCompletionGate x=new TaskCompletionGate(TASK,s,TaskAuthorization.parse(s));check(!TaskCompletionGate.NOTES.equals(x.contract.kind),"unsupported/negated/multiple goal must not inherit note proof");}
            String payload="包含 web.search 和数字 73 的正文";TaskCompletionGate literal=new TaskCompletionGate(TASK,owner(payload),TaskAuthorization.parse(owner(payload)));check(TaskCompletionGate.NOTES.equals(literal.contract.kind)&&payload.equals(literal.contract.body),"literal payload never changes contract kind");
        });
        test("launch_is_not_save_and_two_claims_stop",()->{TaskCompletionGate g=gate();Frame e=launched(g);TaskCompletionGate.Check a=g.successClaim(2,id(2),e);check(!a.verified&&a.retryAllowed,"first premature claim may continue");TaskCompletionGate.Check b=g.successClaim(3,id(3),e);check(!b.verified&&!b.retryAllowed,"second refusal must stop, not a third retry");});
        test("ordered_real_list_same_item_reopen",()->{TaskCompletionGate g=gate();chain(g,false);});
        test("any_list_click_cannot_prove_same_item",()->{TaskCompletionGate g=gate();chain(g,true);});
        test("editor_or_reopen_without_list_never_completes",()->{TaskCompletionGate g=gate();Frame e=launched(g),r=editor();g.action(2,id(2),action(e,"click",null,"n0"),true,true,false,e,r,null);check(!g.verified(r),"editor body readback is not save/list proof");});
        test("preexisting_body_cannot_be_new_entry",()->{TaskCompletionGate g=gate();Frame b=editor(),a=editor();ActionDecision d=action(b,"notes.create",BODY,null);g.action(1,id(1),d,true,true,false,b,a,fixed(b,d,id(1)));check(Boolean.FALSE.equals(g.prompt(a).get("notes_launch_observed")),"same existing editor does not establish new body entry");});
        test("actual_fixed_receipt_identity_required",()->{
            for(String key:Arrays.asList("task_id","model_run_id","observation_id","payload_sha256","attempt_id","source_window_id","display_id")){
                TaskCompletionGate g=gate();Frame b=initial(),a=editor();ActionDecision d=action(b,"notes.create",BODY,null);Map<String,Object> p=fixed(b,d,id(1));p.put(key,key.endsWith("_id")&&("source_window_id".equals(key)||"display_id".equals(key))?99:"wrong");g.action(1,id(1),d,true,true,false,b,a,p);check(!Boolean.TRUE.equals(g.prompt(a).get("notes_launch_observed")),"foreign fixed identity cannot advance: "+key);
            }
        });
        test("cross_display_generation_cannot_complete",()->{TaskCompletionGate g=gate();Frame e=launched(g),l=listing();Frame foreign=new Frame(l.observationId,l.packageName,l.windowId,9,"11111111-1111-1111-1111-111111111111",1,true,false,l.nodes);g.action(2,id(2),action(e,"back",null,null),true,true,false,e,foreign,null);check(!g.verified(foreign),"a display change cannot carry save evidence");});
        test("final_window_change_is_recoverable_missing_evidence",()->{TaskCompletionGate g=gate();Frame e=launched(g);TaskCompletionGate.Check c=g.successClaim(2,id(2),e,false);check(!c.verified&&c.retryAllowed&&Boolean.FALSE.equals(c.evidence.get("final_observation_stable")),"changing final frame is not successful completion");});
        test("unknown_readonly_goal_requires_no_write",()->{String owner="读出当前页面的标题，不要点击或输入。";TaskCompletionGate g=new TaskCompletionGate(TASK,owner,TaskAuthorization.parse(owner));Frame f=initial();g.observed(f);check(!g.verified(f)&&Boolean.FALSE.equals(g.prompt(f).get("writes_required_for_unknown_or_read_only_goal")),"no universal write/effect prerequisite");check(!((List<?>)g.prompt(f).get("missing")).contains("model_bound_notes_create_with_owner_body_missing"),"unknown task cannot acquire a note-writing obligation");for(String key:Arrays.asList("notes_launch_observed","editor_body_observed","list_observed","same_list_item_reopened","web_query_dispatched"))check(!g.prompt(f).containsKey(key),"unknown goal has no irrelevant method stages: "+key);});
        test("web_prompt_contains_only_its_relevant_method_stage",()->{TaskCompletionGate g=new TaskCompletionGate(TASK,WEB,TaskAuthorization.parse(WEB));Map<String,Object> p=g.prompt(initial());check(p.containsKey("web_query_dispatched"),"web method stage remains visible");for(String key:Arrays.asList("notes_launch_observed","editor_body_observed","list_observed","same_list_item_reopened"))check(!p.containsKey(key),"web query has no note-writing stage: "+key);});
    }
    static void installPackage(QualificationScopeHostTest.Env e,String tool)throws Exception{
        ActivityInfo a=FixedIntentIntegrationHostTest.install(e,tool,10382);PackageInfo p=new PackageInfo();p.packageName=a.packageName;p.version=1;p.applicationInfo=a.applicationInfo;
        Path apk=e.dir.resolve("installed/completion-"+tool.replace('.','-')+".apk");QualificationScopeHostTest.write(apk,("synthetic-installed-"+tool).getBytes(StandardCharsets.UTF_8),0644);p.applicationInfo.sourceDir=apk.toString();e.pm.packages.put(p.packageName,p);
    }
    static PhoneObservation.Node row(String id,String pkg,String text,String view,Rect bounds,boolean editable,boolean click,boolean scroll){return new PhoneObservation.Node(id,pkg,"TextView",view,text,"",bounds,click,editable,scroll,true,true,false,ObservedChildText.notApplicable(),ObservedScrollActions.observed(Collections.<String>emptyList()),ObservedImeEnter.UNKNOWN,editable?ObservedImeEnter.hash(text):null,false);}
    static final class Model implements LocalInference {
        final QualificationScopeHostTest.Env e;final String mode,owner;int calls,phase,ends,createdReads;String task;final List<String> prompts=new ArrayList<String>();
        final CountDownLatch finalVerifyEntered=new CountDownLatch(1),releaseFinalVerify=new CountDownLatch(1);
        boolean finalVerifyStackObserved;
        Model(QualificationScopeHostTest.Env e,String mode,String owner){this.e=e;this.mode=mode;this.owner=owner;}
        public LocalRuntimeConfig configuration(){return e.runtime;}
        public void beginTask(String id){task=id;}
        public TaskCleanup endTask(){
            ends++;
            if("close_identity_changed".equals(mode))try{
                QualificationScopeHostTest.write(Paths.get(e.pm.packages.get(P).applicationInfo.sourceDir),"changed installed bytes after completion".getBytes(StandardCharsets.UTF_8),0644);
            }catch(Exception changed){throw new IllegalStateException(changed);}
            if(mode.contains("stop_final_verify"))e.service.packageManagerReadHook=()->{
                for(StackTraceElement frame:Thread.currentThread().getStackTrace())
                    if(frame.getClassName().equals("org.trillionnium.hepta.local.QualificationScopeConfig$CompletionInstalledIdentity")&&"verify".equals(frame.getMethodName()))finalVerifyStackObserved=true;
                if(!finalVerifyStackObserved)throw new AssertionError("IO hook must execute inside actual completion-installed verify");
                e.service.packageManagerReadHook=null;finalVerifyEntered.countDown();
                try{if(!releaseFinalVerify.await(5,TimeUnit.SECONDS))throw new AssertionError("host must release final identity verification");}
                catch(InterruptedException error){Thread.currentThread().interrupt();throw new IllegalStateException(error);}
            };
            if("close_stop_final_verify_unknown_cleanup".equals(mode))return new TaskCleanup(false,true,false,null,id(77),task,false,null);
            return new TaskCleanup(true,true,true,0,id(77),task,!"close_invalid_receipt".equals(mode),H);
        }
        void setup(){
            if(mode.startsWith("detour")){
                e.service.effectHook=()->{
                    if(e.service.opens==1&&phase==0){phase=1;e.service.root.pkg=P;e.service.node.pkg=P;e.service.node.text=BODY;e.service.node.editable=true;}
                    else if(e.service.opens==2&&phase==2){phase=3;e.service.root.pkg=P;e.service.node.pkg=P;e.service.node.editable=false;}
                    else if(e.service.node.actions==1&&phase==3){phase=4;e.service.node.editable=true;}
                };
                e.service.observationRows=()->{
                    if(phase==0||phase==2)return Collections.singletonList(row("n0",e.service.root.pkg,"synthetic unrelated screen","",new Rect(10,10,500,150),false,false,false));
                    // Explicit Android IO: the immediate create-after contains
                    // the full body, but the next fresh read is an incomplete
                    // transient editor. The workflow must stop before a child;
                    // the later model Back then races an external window change.
                    if(phase==1&&++createdReads==2)return Collections.singletonList(row("n0",P,"synthetic pending editor view","",new Rect(10,10,500,150),false,false,false));
                    if(phase==1||phase==4)return Arrays.asList(row("n0",P,BODY,"",new Rect(10,10,500,150),true,true,false),row("n1",P,"NoteEditor","",new Rect(0,0,1080,2400),false,false,true));
                    return Arrays.asList(row("n0",P,BODY,"",new Rect(10,10,500,150),false,true,false),row("n1",P,"",P+":id/view_pager2",new Rect(0,0,1080,2400),false,false,true),row("n2",P,"所有笔记",P+":id/title_text",new Rect(0,0,100,30),false,false,false));
                };
                return;
            }
            e.service.effectHook=()->{
                if(e.service.opens==1&&phase==0){phase=1;e.service.root.pkg=P;e.service.node.pkg=P;e.service.node.text=BODY;e.service.node.editable=true;}
                else if(e.service.navigations==1&&phase==1){phase=2;e.service.node.editable=false;}
                else if(e.service.node.actions==1&&phase==2){phase=3;e.service.node.editable=true;}
            };
            e.service.observationRows=()->{
                if(phase==0)return Collections.singletonList(row("n0",e.service.root.pkg,e.service.node.text,"",new Rect(10,10,500,150),true,true,false));
                if(phase==1||phase==3)return Arrays.asList(row("n0",P,BODY,"",new Rect(10,10,500,150),true,true,false),row("n1",P,"NoteEditor","",new Rect(0,0,1080,2400),false,false,true));
                return Arrays.asList(row("n0",P,BODY,"",new Rect(10,10,500,150),false,true,false),row("n1",P,"",P+":id/view_pager2",new Rect(0,0,1080,2400),false,false,true),row("n2",P,"所有笔记",P+":id/title_text",new Rect(0,0,100,30),false,false,false));
            };
        }
        public Handle generate(String prompt,String system,File image,DecisionGrammar grammar,int maximum,long timeout,Callback callback){
            calls++;prompts.add(prompt);
            try{
                check(prompt.endsWith("\nOWNER\n"+owner)&&prompt.contains("\"completion\":"),"owner unchanged; structured completion included in actual model input");
                JSONObject data=new JSONObject(prompt.substring("UNTRUSTED_DATA\n".length(),prompt.lastIndexOf("\nOWNER\n")));
                check(ActionDecision.FIXED_INTENT_ACTION_SCHEMA.equals(grammar.schema)
                        &&grammar.successAllowed==data.getJSONObject("completion").getBoolean("done_success_eligible"),
                        "current completion eligibility and the actual generated grammar agree");
                String tool="done";
                if("complete".equals(mode)||mode.startsWith("close_")){tool=calls==2?"notes.create":calls==3?"back":calls==4?"click":"done";}
                if(mode.startsWith("detour")){
                    tool=calls==1?"notes.create":calls==2?"back":calls==3?"open":calls==4?"click":"done";
                    if(calls==2){
                        JSONObject parentEvent=data.getJSONArray("events").getJSONObject(0);
                        check(!parentEvent.has("tool_workflow")&&"notes.create".equals(parentEvent.getString("action"))
                                &&parentEvent.getBoolean("model_issued"),"fallback preserves the actual model parent without nested history data");
                        check("tool_workflow".equals(parentEvent.getString("tool_workflow_actor_kind"))
                                &&!parentEvent.getBoolean("tool_workflow_model_issued")&&!parentEvent.getBoolean("tool_workflow_verified"),
                                "incomplete tool workflow remains separate scalar evidence, never a model action or success");
                        check(parentEvent.getString("tool_workflow_id").length()==64
                                &&"step-01-notes-workflow-result.json".equals(parentEvent.getString("tool_workflow_receipt_file")),
                                "flat history retains the exact workflow identity and complete receipt reference");
                        // Explicit Android IO race: the user/system leaves Notes
                        // after this prompt. No model self-app open is authorized.
                        phase=2;e.service.root.pkg="org.trillionnium.hepta.local";
                        e.service.node.pkg=e.service.root.pkg;e.service.node.editable=false;
                    }
                }
                if("draft".equals(mode))tool=calls==1?"notes.create":"done";
                if("web".equals(mode))tool=calls==1?"web.search":"done";
                if("cancel".equals(mode)&&calls==2)e.controller.stop();
                JSONObject a=new JSONObject().put("reason","synthetic native IO choice").put("action",tool).put("observation_id",grammar.observationId);
                if(FixedIntentTools.isTool(tool)){
                    FixedIntentTarget t=grammar.fixedIntentTargets.get(tool);check(t!=null,"fixed tool is actually offered");a.put("app_label",ObservedAppLabels.project(t.appLabel)).put("package",t.packageName).put("notes.create".equals(tool)?"text":"query","notes.create".equals(tool)?BODY:"蓝色水杯 价格");
                }else if("open".equals(tool)){
                    String target=calls==2?"org.trillionnium.hepta.local":P;
                    a.put("app_label",grammar.appLabels.labels.get(target)).put("package",target);
                }else{
                    a.put("package",grammar.currentPackage);
                    if("click".equals(tool))a.put("node_label",ObservedTargetLabels.project(BODY)).put("node_id","n0");
                    if("done".equals(tool)){
                        // The first premature success is deliberately outside
                        // the actual supplied grammar. A following partial is
                        // an explicit fake-model correction, never a controller action.
                        String status=(("draft".equals(mode)||"web".equals(mode))&&calls>=3)?"partial":"success";
                        a.put("status",status).put("summary","模型声明原文不能替代完成证据");
                    }
                }
                callback.onSuccess(a.toString(),id(calls));
            }catch(Exception x){throw new IllegalStateException(x);}return ()->{};
        }
    }
    static void controllerCase(String mode,String owner,boolean verified,int expectedCalls)throws Exception{
        try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            installPackage(e,"notes.create");installPackage(e,"web.search");Model m=new Model(e,mode,owner);if(!"web".equals(mode))m.setup();
            if(mode.startsWith("detour")){e.service.launchable.clear();e.service.launchable.put(P,P);e.service.launchable.put("org.trillionnium.hepta.local","Hepta");}
            e.controller=new LocalTaskController(e.service,m);CountDownLatch done=new CountDownLatch(1);LocalTaskController.TaskResult[] box=new LocalTaskController.TaskResult[1];
            check(e.controller.start(owner,null,new LocalTaskController.Listener(){public void onState(String v){}public void onFinished(LocalTaskController.TaskResult r){box[0]=r;done.countDown();}}),"ordinary task starts");
            if(mode.contains("stop_final_verify")){
                try{check(m.finalVerifyEntered.await(10,TimeUnit.SECONDS),"actual final identity verification reaches Android IO boundary");e.controller.stop();}
                finally{m.releaseFinalVerify.countDown();}
            }
            check(done.await(10,TimeUnit.SECONDS),"ordinary controller finishes");
            boolean cleanupExpected=!"close_stop_final_verify_unknown_cleanup".equals(mode);
            LocalTaskController.TaskResult r=box[0];check(r!=null&&r.cleanupKnown==cleanupExpected&&r.modelReportedSuccess&&r.completionVerified==verified,"raw model claim and independently checked completion separated: "+mode+" / "+(r==null?"null":r.status+" "+r.summary));
            check(m.calls==expectedCalls&&m.ends==1,"bounded continuation and one retained task worker teardown");
            String expectedStatus=!cleanupExpected?"blocked":mode.contains("stop_final_verify")?"cancelled":verified?("complete".equals(mode)?"controller_verified_done":"model_reported_done"):"cancel".equals(mode)?"cancelled":("close_invalid_receipt".equals(mode)||"readonly".equals(mode))?"failed":"partial";
            check(expectedStatus.equals(r.status),"honest terminal status: "+mode+" / "+r.status);
            if(mode.contains("stop_final_verify"))check(m.finalVerifyStackObserved,"Stop occurred while real installed identity verifier was active");
            JSONObject result=FixedIntentIntegrationHostTest.json(r.evidenceDirectory.toPath().resolve("result.json"));check(result.getBoolean("model_reported_success")&&result.getBoolean("completion_verified")==verified,"terminal keeps original native success claim");
            check(result.getString("status").equals(r.status)&&result.getBoolean("cleanup_known")==cleanupExpected,"terminal status and cleanup evidence agree with published result");
            if(mode.startsWith("close_stop_final_verify"))check(result.getBoolean("controller_completion_requested")&&result.isNull("completion_actor"),"late Stop revokes verified controller workflow completion without losing its actual request");
            if("detour_stop_final_verify".equals(mode))check(!result.getBoolean("controller_completion_requested")&&result.isNull("completion_actor"),"late Stop revokes the ordinary model-done completion path");
            check(result.getBoolean("goal_independently_verified")==verified,"independent goal field follows actual supported completion evidence");
            if("complete".equals(mode)){
                check(e.service.opens==1&&e.service.navigations==1&&e.service.node.actions==1,"one actual fixed Intent then actual back and same-node click");
                check(Files.exists(r.evidenceDirectory.toPath().resolve("step-01-budget-1.json"))
                        &&!Files.exists(r.evidenceDirectory.toPath().resolve("step-01-completion-reobserve.json")),
                        "off-grammar first success is rejected before service, with one bounded native format correction");
                JSONObject rejected=new JSONObject(FixedIntentIntegrationHostTest.json(r.evidenceDirectory.toPath().resolve("step-01-model-0.json")).getString("raw_text"));
                check("done".equals(rejected.getString("action"))&&"success".equals(rejected.getString("status")),
                        "original rejected native output stays archived");
                check("controller/tool_workflow".equals(result.getString("completion_actor"))&&!result.getBoolean("model_done_synthesized")
                        &&Files.exists(r.evidenceDirectory.toPath().resolve("step-01-tool-child-01-action.json"))
                        &&!Files.exists(r.evidenceDirectory.toPath().resolve("step-02-model-0.json")),
                        "independent workflow completion preserves the earlier raw claim without inventing later model actions");
            }
            if(mode.startsWith("detour")){
                check(e.service.opens==2&&e.service.navigations==0&&e.service.node.actions==1,"external window change is reobserved; model opens only Notes then clicks its same item");
                JSONObject stale=FixedIntentIntegrationHostTest.json(r.evidenceDirectory.toPath().resolve("step-02-action.json"));
                check(stale.getBoolean("stale")&&!stale.getBoolean("dispatched"),"outdated editor navigation never dispatches after external window change");
                JSONObject workflow=FixedIntentIntegrationHostTest.json(r.evidenceDirectory.toPath().resolve("step-01-notes-workflow-result.json"));
                check(!workflow.getBoolean("workflow_verified")&&"fresh_created_body_or_unique_list_unavailable".equals(workflow.getString("stop_reason"))
                        &&!Files.exists(r.evidenceDirectory.toPath().resolve("step-01-tool-child-01-action.json")),
                        "incomplete fresh editor stops the workflow with zero children; only later real model navigation can recover");
            }
            if("readonly".equals(mode)||"cancel".equals(mode)){
                check(e.service.effects()==0,"read-only unknown task was never forced to write or navigate");
                check(!Files.exists(r.evidenceDirectory.toPath().resolve("step-01-action.json")),"invalid success never reaches even a no-effect service done callback");
                check(result.getJSONObject("completion_evidence").getInt("rejected_success_claims")==0,
                        "front-end eligibility rejection is distinct from a final provider rejection");
            }
            if("draft".equals(mode))check(e.service.opens==1&&e.service.navigations==0&&e.service.node.actions==0
                    &&!Files.exists(r.evidenceDirectory.toPath().resolve("step-01-notes-workflow-grant-consumed.json")),
                    "an explicit no-save OWNER keeps draft-only behavior with no workflow or replay");
            if("web".equals(mode))check(e.service.opens==1&&result.getJSONObject("completion_evidence").getBoolean("web_query_dispatched"),"web method executed exactly once but result proof unavailable");
            if(mode.startsWith("close_")){check(e.service.opens==1&&e.service.navigations==1&&e.service.node.actions==1,"completed visible chain is not replayed when terminal verification fails");check(FixedIntentIntegrationHostTest.json(r.evidenceDirectory.toPath().resolve("step-01-notes-workflow-result.json")).getBoolean("accepted_as_completion_proof")
                    &&Files.exists(r.evidenceDirectory.toPath().resolve("controller-completion-candidate.json")),"the actual child chain verified before blocking model close");check(!result.getJSONObject("completion_evidence").getBoolean("terminal_binding_and_cleanup_verified"),"post-close failure removes verified completion without erasing raw model claim");}
        }
    }
    static void bridgeCase()throws Exception{
        java.lang.reflect.Method bridge=LocalTaskController.class.getDeclaredMethod("completionFrame",PhoneObservation.class);bridge.setAccessible(true);
        try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            ObservedChildText.Result truncated=new ObservedChildText.Result(BODY,"derived",true,1,Collections.<ObservedChildText.Source>emptyList());
            PhoneObservation.Node n=new PhoneObservation.Node("n0",P,"TextView","",""," ",new Rect(10,100,600,300),true,false,false,true,false,false,truncated,ObservedScrollActions.UNKNOWN);
            PhoneObservation base=e.service.current;PhoneObservation o=new PhoneObservation(base.id,P,base.capturedElapsedMillis,1080,2400,0,7,new Rect(0,0,1080,2400),base.screenshot,H,H,base.state,base.windowMetadata,false,Collections.singletonList(n));
            Frame f=(Frame)bridge.invoke(null,o);check(f.nodes.get(0).label.isEmpty(),"whitespace direct text must not hide a truncated derived label");
        }
    }
    public static void main(String[] args)throws Exception{
        output=Paths.get(args[0]);Files.createDirectories(output);QualificationScopeHostTest.output=output;
        pureCases();test("bridge_clears_whitespace_masked_truncated_child",()->bridgeCase());
        test("actual_controller_first_done_recovers_and_real_note_chain_completes",()->controllerCase("complete",OWNER,true,2));
        test("actual_controller_external_window_detour_recovers_only_after_same_item_click",()->controllerCase("detour",OWNER,true,5));
        test("actual_controller_draft_only_done_remains_partial_once",()->controllerCase("draft",DRAFT_OWNER,false,3));
        test("actual_controller_web_effect_without_results_is_partial",()->controllerCase("web",WEB,false,3));
        test("actual_controller_unknown_readonly_two_claims_zero_effects",()->controllerCase("readonly","读出当前页面的标题，不要点击或输入。",false,2));
        test("actual_controller_cancel_after_rejection_stops_without_effect",()->controllerCase("cancel","读出当前页面的标题。",false,2));
        test("actual_controller_installed_identity_rechecked_after_close",()->controllerCase("close_identity_changed",OWNER,false,2));
        test("actual_controller_bad_native_close_receipt_cannot_complete",()->controllerCase("close_invalid_receipt",OWNER,false,2));
        test("actual_controller_stop_during_final_identity_verify_cancels_workflow",()->controllerCase("close_stop_final_verify",OWNER,false,2));
        test("actual_controller_stop_during_final_identity_verify_cancels_model_done",()->controllerCase("detour_stop_final_verify",OWNER,false,5));
        test("actual_controller_stop_during_final_identity_verify_preserves_unknown_cleanup_block",()->controllerCase("close_stop_final_verify_unknown_cleanup",OWNER,false,2));
        Files.write(output.resolve("TEST-RESULTS.json"),new JSONObject().put("all_pass",true).put("cases",passed).put("checks",passed.size()).put("actual_controller",true).put("android_and_model_io_are_fakes",true).put("phone_tested",false).toString(2).getBytes(StandardCharsets.UTF_8));
    }
}
