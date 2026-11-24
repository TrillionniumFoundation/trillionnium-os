package org.trillionnium.hepta.local;

import android.graphics.Rect;
import java.io.File;
import java.lang.reflect.Field;
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
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.FixedIntentTarget;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Frame;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Node;

/** Actual immutable-owner parser, selection, completion, phase, grammar,
 * controller start and workflow. Android/model/child IO is explicitly synthetic.
 * The recorded phone owner and failed result are never relabelled as a pass. */
public final class NotesAppQualifiedCreateHostTest {
    static final String TASK="11111111111111111111111111111111";
    static final String P=NotesCompletionEvidence.NOTES;
    static final String H="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static final String OWNER="在备忘录里新建一条备忘录：本机手动模型测试青岚四二八七。";
    static final String BODY="本机手动模型测试青岚四二八七。";
    static final String OWNER_SHA="9bd4490f400dd0bd3911a38f8389453bef31c5984696e9d741f9acf95c0122a0";
    static int checks,serial=21000;
    static final List<String> cases=new ArrayList<String>();
    static final List<Object> grammarCases=new ArrayList<Object>();
    interface Work {void run()throws Exception;}
    static void check(boolean value,String why){checks++;if(!value)throw new AssertionError(why);}
    static void test(String name,Work work)throws Exception{work.run();cases.add(name);System.out.println("PASS "+name);}
    static void denied(Work work,String why)throws Exception{
        boolean no=false;try{work.run();}catch(IllegalArgumentException|IllegalStateException expected){no=true;}
        check(no,why);
    }
    static String id(){return String.format(java.util.Locale.ROOT,"%032x",++serial);}
    static String hash(String text){return ObservedImeEnter.hash(text);}
    static String repeat(String s,int n){StringBuilder b=new StringBuilder();for(int i=0;i<n;i++)b.append(s);return b.toString();}
    static Set<String> set(String... values){return new TreeSet<String>(Arrays.asList(values));}
    static BackgroundSession.Selection selection(String owner,String pkg){
        return new BackgroundSession.Selection(BackgroundTaskTarget.resolveExplicitSelection(owner,pkg,Collections.singleton(pkg)));
    }
    static TaskAuthorization authorization(String owner,BackgroundSession.Selection s){
        return TaskAuthorization.parse(owner).forExecutionSelection(s);
    }
    static void contract(String owner,String body,boolean newForm)throws Exception{
        BackgroundSession.Selection s=selection(owner,P);TaskAuthorization a=authorization(owner,s);
        TaskCompletionGate.requireSupportedNotesCreate(owner,a,s);
        TaskCompletionGate g=new TaskCompletionGate(TASK,owner,a,s);
        check(TaskCompletionGate.NOTES.equals(g.contract.kind)&&body.equals(g.contract.body),"complete original Notes contract "+owner);
        check(owner.equals(a.immutableOwner())&&hash(owner).equals(a.instructionSha256),"entire immutable OWNER identity");
        check(a.allowedTools.contains("notes.create")&&!a.allowedTools.contains("web.search"),"original explicit native authority ceiling");
        if(newForm){
            NotesOwnerIntent.Result n=NotesOwnerIntent.parse(owner);
            check(n.supported&&body.equals(n.body)&&body.equals(owner.substring(n.bodyStartUtf16,n.bodyEndUtf16)),"exact UTF-16 body span");
            check(!n.masksOwnerBodyForAuthority()&&owner.equals(n.maskedOwnerForAuthority(owner)),"new form never masks the authority compiler");
            check(!n.grantsToolAuthority&&n.saveAndReopenRequested&&!n.draftOnly,"parser requests verification but grants no effect");
            denied(()->n.maskedOwnerForAuthority(owner+"再删除"),"changed OWNER cannot borrow body proof");
        }
    }
    static void rejectCreate(String owner)throws Exception{
        BackgroundSession.Selection s=selection(owner,P);TaskAuthorization a=authorization(owner,s);
        check(NotesOwnerIntent.explicitCreateRequest(owner),"explicit create must reach admission: "+owner);
        check(!TaskCompletionGate.NOTES.equals(TaskCompletionGate.Contract.parse(owner,a).kind),"unsupported body cannot become Notes contract");
        denied(()->TaskCompletionGate.requireSupportedNotesCreate(owner,a,s),"unsupported explicit Notes create cannot fall into generic writes: "+owner);
    }
    static Frame editor(String body){
        return new Frame(id(),P,7,0,null,1,true,false,Arrays.asList(
            TaskCompletionGateHostTest.n("n0",P,body,"",new int[]{10,100,600,500},true,true,false),
            TaskCompletionGateHostTest.n("n1",P,"NoteEditor","",new int[]{0,0,1000,2000},false,false,true)));
    }
    static Frame listing(String body){
        return new Frame(id(),P,7,0,null,1,true,false,Arrays.asList(
            TaskCompletionGateHostTest.n("n0",P,body,"",new int[]{10,100,600,300},false,true,false),
            TaskCompletionGateHostTest.n("n1",P,"",P+":id/view_pager2",new int[]{0,80,1000,2000},false,false,true),
            TaskCompletionGateHostTest.n("n2",P,"所有笔记",P+":id/title_text",new int[]{0,0,300,80},false,false,false)));
    }
    static NotesCreateWorkflow.Observation observed(Frame f){return new NotesCreateWorkflow.Observation(f,H,0);}
    static Map<String,FixedIntentTarget> targets(){return Collections.singletonMap("notes.create",new FixedIntentTarget("notes.create","Moto 笔记",10382,null));}
    static ActionDecision create(Frame before,String body)throws Exception{
        return ActionDecision.parse(new JSONObject().put("reason","synthetic model parent using the real grammar")
            .put("action","notes.create").put("observation_id",before.observationId)
            .put("app_label","Moto 笔记").put("package",P).put("text",body).toString(),ActionDecision.FIXED_INTENT_ACTION_SCHEMA);
    }
    static void grammarCase(String name,DecisionGrammar grammar,String raw,boolean accepted){
        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);row.put("grammar",grammar.text);
        row.put("json",raw);row.put("accepted",accepted);grammarCases.add(row);
    }
    static Object field(Object o,String name)throws Exception{Field f=o.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(o);}
    static PhoneObservation phone(Frame frame){
        List<PhoneObservation.Node> nodes=new ArrayList<PhoneObservation.Node>();
        for(Node n:frame.nodes)nodes.add(new PhoneObservation.Node(n.id,n.packageName,"TextView",n.viewId,n.text,"",
            new Rect(n.bounds()[0],n.bounds()[1],n.bounds()[2],n.bounds()[3]),n.clickable,n.editable,n.scrollable,n.enabled,true,n.password,
            ObservedChildText.notApplicable(),ObservedScrollActions.observed(Collections.<String>emptyList()),ObservedImeEnter.UNKNOWN,n.inputTextSha256,false));
        int[] b={0,0,1080,2400};
        return new PhoneObservation(frame.observationId,P,android.os.SystemClock.elapsedRealtime(),1080,2400,0,7,new Rect(0,0,1080,2400),
            new File("synthetic-not-a-phone-screenshot"),H,H,new ObservationState(H,ImeVisibility.HIDDEN),
            ObservedWindowMetadata.observed(b,"android.widget.FrameLayout",1,0,b,"Moto 笔记"),false,nodes);
    }
    static void phaseAndActualPrompt()throws Exception{
        BackgroundSession.Selection s=selection(OWNER,P);TaskAuthorization a=authorization(OWNER,s);
        TaskAuthorization.Gate auth=a.bind(TASK);TaskCompletionGate g=new TaskCompletionGate(TASK,OWNER,a,s);
        g.bindInstalled(new NotesCompletionEvidence.Installed(P,10382,Collections.singletonMap("base",H)));
        Frame before=editor("旧笔记应保持不变");g.observed(before);
        NotesTaskPhaseGuard guard=new NotesTaskPhaseGuard(TASK,a);
        NotesTaskPhaseGuard.Projection phase=guard.prepare(g,before);
        check(guard.supported()&&"create_required".equals(phase.phase),"real contract produces create_required on an existing editor");
        check(phase.clicks(set("n0")).isEmpty()&&phase.edits(set("n0")).isEmpty(),"existing note click and text replacement are removed");
        Map<String,FixedIntentTarget> fixed=phase.fixedTargets(targets());
        check(BODY.equals(phase.exactPayloads(fixed).get("notes.create")),"exact payload includes original full stop");
        check(g.notesCreateWorkflowRequested(auth.frame()),"original bounded save/list/reopen workflow requested");
        Method helper=NotesTaskPhaseHostTest.class.getDeclaredMethod("prompt",String.class,PhoneObservation.class,
            TaskAuthorization.Gate.class,TaskCompletionGate.class,NotesTaskPhaseGuard.class);
        helper.setAccessible(true);
        Object produced=helper.invoke(null,OWNER,phone(before),auth,g,guard);
        String prompt=(String)field(produced,"text");DecisionGrammar grammar=(DecisionGrammar)field(produced,"grammar");
        check(prompt.endsWith("\nOWNER\n"+OWNER),"actual controller prompt preserves entire OWNER");
        JSONObject json=new JSONObject(prompt.substring("UNTRUSTED_DATA\n".length(),prompt.indexOf("\nOWNER\n")));
        check("create_required".equals(json.getJSONObject("task_phase").getString("phase")),"actual prompt includes bounded phase");
        JSONArray tools=json.getJSONArray("fixed_intent_tools");boolean tool=false;
        for(int i=0;i<tools.length();i++){JSONObject row=tools.getJSONObject(i);if("notes.create".equals(row.getString("action"))){
            tool=true;check("create_then_bounded_save_list_reopen_tool_children".equals(row.getString("owner_bound_execution_mode")),
                "actual prompt advertises existing bounded child mode only under the new valid contract");}}
        check(tool&&!grammar.successAllowed,"fixed entry supplied without premature success");
        String exact=new JSONObject().put("reason","按本轮新建目标").put("action","notes.create").put("observation_id",before.observationId)
            .put("app_label","Moto 笔记").put("package",P).put("text",BODY).toString();
        grammarCase("exact_original_body_with_full_stop",grammar,exact,true);
        grammarCase("missing_owner_full_stop",grammar,exact.replace(BODY,BODY.substring(0,BODY.length()-1)),false);
        grammarCase("different_body",grammar,exact.replace(BODY,"其他正文"),false);
        String click=new JSONObject().put("reason","不能编辑旧笔记").put("action","click").put("observation_id",before.observationId)
            .put("package",P).put("node_label","旧笔记应保持不变").put("node_id","n0").toString();
        String type=new JSONObject().put("reason","不能覆盖旧笔记").put("action","type").put("observation_id",before.observationId)
            .put("package",P).put("node_label","旧笔记应保持不变").put("node_id","n0").put("text",BODY).toString();
        grammarCase("existing_note_click",grammar,click,false);grammarCase("existing_note_type",grammar,type,false);
        denied(()->guard.requireCurrent(ActionDecision.parse(click,ActionDecision.FIXED_INTENT_ACTION_SCHEMA)),"phase dispatch independently refuses old note click");
        denied(()->guard.requireCurrent(ActionDecision.parse(type,ActionDecision.FIXED_INTENT_ACTION_SCHEMA)),"phase dispatch independently refuses old note replacement");
        guard.requireCurrent(create(before,BODY));
        check(!g.verified(before),"grammar availability and phase do not constitute completion");
    }
    static void boundedWorkflow()throws Exception{
        BackgroundSession.Selection s=selection(OWNER,P);TaskAuthorization a=authorization(OWNER,s);
        TaskAuthorization.Gate auth=a.bind(TASK);TaskCompletionGate g=new TaskCompletionGate(TASK,OWNER,a,s);
        g.bindInstalled(new NotesCompletionEvidence.Installed(P,10382,Collections.singletonMap("base",H)));
        Frame before=editor("不同的旧笔记"),created=editor(BODY);g.observed(before);
        ActionDecision parent=create(before,BODY);String run=id();
        check(g.notesCreateWorkflow(1,run,parent,observed(created),auth.frame())==null,"no grant before actual accepted parent record");
        FixedIntentAttemptGuard ledger=new FixedIntentAttemptGuard(TASK,proof->{});
        FixedIntentAttemptGuard.Attempt attempt=ledger.consume(new FixedIntentAttemptGuard.Binding(TASK,run,before.observationId,P,
            before.windowId,before.displayId,before.backgroundGeneration,targets().get("notes.create"),BODY));
        ledger.entering(attempt);Map<String,Object> fixed=ledger.finished(attempt,true);
        g.action(1,run,parent,true,true,false,before,created,fixed);
        NotesCreateWorkflow.Grant grant=g.notesCreateWorkflow(1,run,parent,observed(created),auth.frame());
        check(grant!=null&&!g.verified(created),"parent creates only a bounded grant, not save proof");
        Frame fresh=editor(BODY),list=listing(BODY),reopen=editor(BODY),stable=editor(BODY);
        NotesCreateWorkflowHostTest.FakeIO io=new NotesCreateWorkflowHostTest.FakeIO(grant,observed(fresh),observed(list),observed(reopen),observed(stable));
        NotesCreateWorkflow.Result done=NotesCreateWorkflow.run(grant,observed(created),io);
        check(done.completeFor(grant)&&io.effects==2&&io.observations==4,"synthetic IO must actually execute bounded Back, same-item click and stable reopen");
        check(g.notesCreateWorkflowCompleted(done,stable)&&g.controllerWorkflowReady(stable),"original completion gate consumes exact full child proof");
        check(Boolean.FALSE.equals(done.evidence().get("persistent_storage_bytes_verified")),"host workflow does not prove phone storage bytes");
        denied(()->NotesCreateWorkflow.run(grant,observed(created),io),"one-use grant cannot replay");
    }
    static final class NeverModel implements LocalInference {
        final LocalRuntimeConfig runtime;int calls,begins;
        NeverModel(LocalRuntimeConfig r){runtime=r;}
        public LocalRuntimeConfig configuration(){return runtime;}
        public void beginTask(String task){begins++;throw new AssertionError("model reservation forbidden in admission test");}
        public Handle generate(String p,String s,File image,DecisionGrammar g,int n,long t,Callback c){calls++;throw new AssertionError("native generation forbidden");}
    }
    static void actualStart(String owner,String pkg,boolean shouldReject)throws Exception{
        try(QualificationScopeHostTest.Env env=new QualificationScopeHostTest.Env(false)){
            NeverModel model=new NeverModel(env.runtime);env.controller=new LocalTaskController(env.service,model);
            check(env.service.acquireTask(env.task,()->{}),"independent existing lease makes any admission fallthrough observable as false");
            BackgroundSession.Selection s=selection(owner,pkg);TaskAuthorization a=authorization(owner,s);
            boolean thrown=false,result=true;
            try{result=env.controller.start(owner,null,a,s,new LocalTaskController.Listener(){
                public void onState(String state){throw new AssertionError("no task state callback before admission");}
                public void onFinished(LocalTaskController.TaskResult r){throw new AssertionError("no task terminal before admission");}
            });}catch(IllegalArgumentException expected){thrown=true;check(expected.getMessage().contains("无法确定新建备忘录"),"actual start must reject for the specific Notes body admission");}
            check(thrown==shouldReject,"actual controller admission expectation: "+owner);
            if(!shouldReject)check(!result,"accepted semantic request stops at unchanged pre-existing service lease");
            check(model.calls==0&&model.begins==0&&!env.controller.isRunning()&&env.controller.currentTaskId()==null,"no model, worker task or controller task identity acquired");
            check(env.service.opens==0&&env.service.navigations==0&&env.service.gestures==0,"no bootstrap or UI effect");
            check(env.task.equals(field(env.service,"lease")),"old service lease preserved");
        }
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IllegalArgumentException("exact recorded fixture and new output directory required");
        Path out=Paths.get(args[1]);Files.createDirectories(out);QualificationScopeHostTest.output=out;
        test("recorded_50af_owner_bytes_remain_failed_phone_evidence",()->{
            JSONObject f=new JSONObject(new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8));
            String raw=f.getJSONObject("owner").getString("raw_utf8");
            check(OWNER_SHA.equals(hash(raw))&&OWNER_SHA.equals(f.getJSONObject("owner").getString("sha256")),"exact recorded owner bytes and hash");
            JSONObject owner=new JSONObject(raw);
            check(OWNER.equals(owner.getString("instruction"))&&"50af2f83cdb849d4adf28b3b19437909".equals(owner.getString("task_id")),"real failed natural owner");
            check("unverified_goal".equals(owner.getJSONObject("completion_contract").getString("kind")),"historical unknown contract preserved");
            check(!f.getJSONObject("original_terminal_summary").getBoolean("completion_verified")
                &&"blocked".equals(f.getJSONObject("original_terminal_summary").getString("status")),"historical phone failure is not upgraded");
            contract(OWNER,BODY,true);
        });
        test("anchored_app_colon_variants_and_literal_spans",()->{
            contract("请帮我在 Moto 笔记中新建一条笔记:  精确空格  ","  精确空格  ",true);
            contract("在笔记里新建一个笔记：“引号中的正文”","引号中的正文",true);
            contract("在备忘录里新建一条备忘录："+repeat("字",94),repeat("字",94),true);
            contract("在备忘录里新建一条备忘录："+repeat("😀",47),repeat("😀",47),true);
        });
        test("explicit_unknown_body_and_additional_goals_refuse_generic_writes",()->{
            for(String owner:new String[]{"在备忘录里新建一条备忘录：","在备忘录里新建一条备忘录",
                "在备忘录里新建一条备忘录：  ","在备忘录里新建一条备忘录："+repeat("字",95),
                "请帮我在 Moto 笔记中新建一条笔记:  精确空格。  ",
                "在备忘录里新建一条备忘录：牛奶，然后删除旧笔记","在备忘录里新建一条备忘录：牛奶；再查机票",
                "在备忘录里新建一条备忘录：牛奶\n鸡蛋","在备忘录里新建并保存一条备忘录",
                "新建一条笔记内容为牛奶","新建一条备忘录然后删除旧笔记",
                "新建一条笔记，但只打开一个空草稿，然后删除旧笔记"})rejectCreate(owner);
        });
        test("original_quoted_and_long_complete_workflows_remain_supported",()->{
            contract("在 Moto 笔记里新建并保存一条备忘录，正文是“柏影七三一六”，然后从列表重新打开核对正文。","柏影七三一六",false);
            contract(TaskCompletionGateHostTest.owner("原先的完整正文。"),"原先的完整正文。",false);
            contract("创建一条备忘录，内容为：“牛奶，然后支付”","牛奶，然后支付",false);
        });
        test("closed_empty_draft_and_other_app_or_existing_note_are_not_promoted",()->{
            for(String owner:new String[]{"在备忘录里只打开一个空白笔记草稿","新建一条笔记，但只打开一个空草稿，不保存。"}){
                BackgroundSession.Selection s=selection(owner,P);TaskAuthorization a=authorization(owner,s);
                check(NotesOwnerIntent.explicitEmptyDraftRequest(owner),"complete empty-draft exception");
                TaskCompletionGate.requireSupportedNotesCreate(owner,a,s);
                check(!TaskCompletionGate.NOTES.equals(new TaskCompletionGate(TASK,owner,a,s).contract.kind),"draft exemption never gains persistence proof");
            }
            for(String owner:new String[]{"请只打开笔记草稿，不要保存。","新建一条笔记，只打开一个空草稿，不保存。",
                "新建一条笔记，只打开空白草稿，然后删除旧笔记"}){
                boolean refused=false;try{TaskAuthorization.parse(owner);}catch(TaskAuthorization.Violation expected){refused=true;}
                check(refused,"unchanged original authorization rejects malformed only-tool clauses before the new admission");
            }
            for(String owner:new String[]{"修改现有备忘录的标题。","读出当前笔记。","新建笔记本的帮助在哪里"}){
                BackgroundSession.Selection s=selection(owner,P);TaskAuthorization a=authorization(owner,s);
                TaskCompletionGate.requireSupportedNotesCreate(owner,a,s);
                check(!NotesOwnerIntent.explicitCreateRequest(owner),"unrelated task not misclassified as this new-note request");
            }
            BackgroundSession.Selection other=selection("新建一条笔记内容为牛奶","com.xiaomi.shop");
            TaskAuthorization a=authorization("新建一条笔记内容为牛奶",other);
            TaskCompletionGate.requireSupportedNotesCreate(a.immutableOwner(),a,other);
            check(TaskCompletionGate.UNKNOWN.equals(new TaskCompletionGate(TASK,a.immutableOwner(),a,other).contract.kind),"other explicit app not converted into Notes");
        });
        test("owner_and_selection_identity_cannot_be_borrowed",()->{
            BackgroundSession.Selection s=selection(OWNER,P);TaskAuthorization a=authorization(OWNER,s);
            denied(()->TaskCompletionGate.requireSupportedNotesCreate(OWNER+"另一个任务",a,s),"changed owner");
            denied(()->TaskCompletionGate.requireSupportedNotesCreate(OWNER,a,selection(OWNER,P)),"equal-looking replaced selection");
            denied(()->TaskCompletionGate.requireSupportedNotesCreate(OWNER,TaskAuthorization.parse(OWNER),s),"unbound authorization");
        });
        test("actual_prompt_phase_exact_grammar_and_old_note_refusal",NotesAppQualifiedCreateHostTest::phaseAndActualPrompt);
        test("actual_bounded_workflow_requires_parent_and_complete_child_proof",NotesAppQualifiedCreateHostTest::boundedWorkflow);
        test("actual_controller_start_rejects_before_uuid_lease_worker_bootstrap",()->{
            for(String owner:new String[]{"在备忘录里新建一条备忘录：","在备忘录里新建一条备忘录：牛奶，然后删除旧笔记",
                "在备忘录里新建并保存一条备忘录","新建一条笔记内容为牛奶"})actualStart(owner,P,true);
        });
        test("actual_controller_start_preserves_supported_draft_and_other_app_admission",()->{
            actualStart(OWNER,P,false);
            actualStart("在 Moto 笔记里新建并保存一条备忘录，正文是“柏影七三一六”，然后从列表重新打开核对正文。",P,false);
            actualStart(TaskCompletionGateHostTest.owner("旧的完整格式。"),P,false);
            actualStart("新建一条笔记，但只打开一个空草稿，不保存。",P,false);
            actualStart("修改现有备忘录的标题。",P,false);
            actualStart("新建一条笔记内容为牛奶","com.xiaomi.shop",false);
        });
        Files.write(out.resolve("grammar-cases.json"),new JSONArray(grammarCases).toString().getBytes(StandardCharsets.UTF_8));
        JSONObject result=new JSONObject().put("all_pass",true).put("cases",cases).put("checks",checks)
            .put("recorded_phone_result_unchanged","blocked").put("all_effect_and_model_io_synthetic",true)
            .put("actual_controller_start_executed",true).put("phone_operations",0).put("native_inference",false);
        Files.write(out.resolve("CASES.json"),result.toString(2).getBytes(StandardCharsets.UTF_8));
        System.out.println("APP_QUALIFIED_NOTES_CASES="+cases.size());
        System.out.println("APP_QUALIFIED_NOTES_ASSERTIONS="+checks);
    }
}
