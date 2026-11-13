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

/** Production restrictions, grammar, prompt and service dispatch. Saved phone
 * frames are replay inputs; synthetic Android/model IO is never device proof. */
public final class NotesTaskPhaseHostTest {
    private static final String FIXTURE_SHA="963f320837ff09709ce10416bcd974d61a94b33d79bcf18b72ae6635becf5696";
    private static final String P=NotesCompletionEvidence.NOTES,TASK="883a2a7d9abd4a25aa44c7e5da21c5be";
    private static final String BODY="Hepta-v45r1-fa929fc0cc3c。购物清单：牛奶、鸡蛋、面包。";
    private static final LocalRuntimeConfig CONFIG=new LocalRuntimeConfig(ModelProfile.GEMMA4_E4B,"npu",8192,4);
    private static JSONObject savedFiles;private static int checks;
    private static final List<Object> grammarCases=new ArrayList<Object>();
    private interface Call {void run()throws Exception;}
    private static void check(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
    private static void denied(Call call,String why)throws Exception{
        try{call.run();throw new AssertionError(why+": accepted");}
        catch(IllegalStateException expected){checks++;}
        catch(ActionDecision.InvalidActionException expected){checks++;}
    }
    private static Set<String> set(String... values){return new TreeSet<String>(Arrays.asList(values));}
    private static JSONObject saved(String name)throws Exception{
        JSONObject entry=savedFiles.getJSONObject(name);String raw=entry.getString("raw_utf8");
        check(entry.getString("sha256").equals(ObservedImeEnter.hash(raw)),"verbatim original bytes: "+name);
        return new JSONObject(raw);
    }
    private static String string(JSONObject o,String key,String fallback)throws Exception{return o.has(key)&&o.get(key)!=JSONObject.NULL?o.getString(key):fallback;}
    private static int[] bounds(JSONArray a)throws Exception{return new int[]{((Number)a.get(0)).intValue(),((Number)a.get(1)).intValue(),((Number)a.get(2)).intValue(),((Number)a.get(3)).intValue()};}
    private static Rect rect(int[] b){return new Rect(b[0],b[1],b[2],b[3]);}
    private static Frame frame(JSONObject raw)throws Exception{
        String pkg=raw.getString("package");List<Node> nodes=new ArrayList<Node>();JSONArray rows=raw.getJSONArray("nodes");
        for(int i=0;i<rows.length();i++){
            JSONObject n=rows.getJSONObject(i);String text=string(n,"text",""),description=string(n,"description","");
            String label=!text.trim().isEmpty()?text:!description.trim().isEmpty()?description:"";
            nodes.add(new Node(n.getString("id"),pkg,text,label,string(n,"view_id",""),string(n,"input_text_sha256",null),
                    bounds(n.getJSONArray("bounds")),n.optBoolean("editable",false),n.optBoolean("clickable",false),n.optBoolean("scrollable",false),n.optBoolean("enabled",true),n.optBoolean("password",false)));
        }
        JSONObject w=raw.getJSONObject("window");
        // Per-node package is not serialized in this historical PhoneObservation.
        // The recorded active package is explicit replay IO, not extra phone proof.
        return new Frame(raw.getString("observation_id"),pkg,raw.getInt("window_id"),w.getInt("display_id"),null,w.getInt("type"),
                "observed".equals(w.getString("metadata_status")),raw.getBoolean("nodes_truncated"),nodes);
    }
    private static PhoneObservation phone(JSONObject raw)throws Exception{
        Frame f=frame(raw);List<PhoneObservation.Node> nodes=new ArrayList<PhoneObservation.Node>();
        for(Node n:f.nodes)nodes.add(new PhoneObservation.Node(n.id,n.packageName,"",n.viewId,n.text,"",rect(n.bounds()),n.clickable,n.editable,n.scrollable,n.enabled,true,n.password,
                ObservedChildText.notApplicable(),ObservedScrollActions.UNKNOWN,ObservedImeEnter.UNKNOWN,n.inputTextSha256,false));
        JSONObject w=raw.getJSONObject("window");
        ObservedWindowMetadata metadata=ObservedWindowMetadata.observed(bounds(w.getJSONArray("root_bounds")),w.getString("root_class"),w.getInt("type"),w.getInt("display_id"),bounds(w.getJSONArray("bounds")),w.getString("title"));
        return new PhoneObservation(f.observationId,f.packageName,android.os.SystemClock.elapsedRealtime(),raw.getInt("screen_width"),raw.getInt("screen_height"),raw.getInt("rotation"),f.windowId,
                rect(bounds(w.getJSONArray("bounds"))),new File("saved-phone-regression-not-a-live-screenshot"),raw.getString("screen_sha256"),raw.getString("observation_state_sha256"),
                state(raw),metadata,f.nodesTruncated,nodes);
    }
    private static ObservationState state(JSONObject raw)throws Exception{return new ObservationState(raw.getString("app_tree_sha256"),raw.getBoolean("ime_visible")?ImeVisibility.VISIBLE:ImeVisibility.HIDDEN);}
    private static ActionDecision action(JSONObject receipt)throws Exception{return ActionDecision.parse(receipt.getJSONObject("action").toString(),ActionDecision.FIXED_INTENT_ACTION_SCHEMA);}
    private static Map<String,FixedIntentTarget> targets(){return Collections.singletonMap("notes.create",new FixedIntentTarget("notes.create","Moto 笔记",10382,null));}
    private static TaskCompletionGate completion(String task,String owner,TaskAuthorization auth,Frame before){
        TaskCompletionGate g=new TaskCompletionGate(task,owner,auth);g.bindInstalled(new NotesCompletionEvidence.Installed(P,10382,Collections.singletonMap("base",NotesCompletionEvidence.OBSERVED_BASE_APK_SHA256)));g.observed(before);return g;
    }
    private static ActionDecision create(Frame before,String body)throws Exception{
        return ActionDecision.parse(new JSONObject().put("reason","host-native-choice-fixture").put("action","notes.create").put("observation_id",before.observationId)
                .put("app_label","Moto 笔记").put("package",P).put("text",body).toString(),ActionDecision.FIXED_INTENT_ACTION_SCHEMA);
    }
    private static Map<String,Object> fixed(String task,Frame before,ActionDecision action,String run)throws Exception{
        FixedIntentAttemptGuard g=new FixedIntentAttemptGuard(task,a->{});FixedIntentAttemptGuard.Attempt a=g.consume(new FixedIntentAttemptGuard.Binding(task,run,before.observationId,before.packageName,
                before.windowId,before.displayId,before.backgroundGeneration,targets().get("notes.create"),action.text));g.entering(a);return g.finished(a,true);
    }
    private static NotesTaskPhaseGuard.Domain bind(NotesTaskPhaseGuard guard,NotesTaskPhaseGuard.Projection p){
        NotesTaskPhaseGuard.Domain d=p.bind(p.clicks(set("n0","n1","n11","n15")),p.edits(set("n11","n15")),p.submits(Collections.singletonMap("n11",Boolean.TRUE)).keySet(),p.fixedTargets(targets()));guard.publish(d);return d;
    }
    private static Object field(Object object,String name)throws Exception{Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(object);}
    private static void field(Object object,String name,Object value)throws Exception{Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);f.set(object,value);}
    private static Object prompt(String owner,PhoneObservation observed,TaskAuthorization.Gate auth,TaskCompletionGate completion,NotesTaskPhaseGuard guard)throws Exception{
        Map<String,String> apps=new LinkedHashMap<String,String>();apps.put(P,"Moto 笔记");apps.put("org.trillionnium.hepta.local","Hepta");
        for(Method m:LocalTaskController.class.getDeclaredMethods())if("prompt".equals(m.getName())&&m.getParameterTypes()[m.getParameterTypes().length-1]==NotesTaskPhaseGuard.class){
            m.setAccessible(true);return m.invoke(null,owner,new AppCatalogueRanker(apps,owner).search("",0),observed,new JSONArray(),null,null,null,CONFIG,
                    new RepeatActionGuard(),new SameStateNoEffectGuard(),auth.frame(),null,targets(),completion,guard);
        }
        throw new AssertionError("actual production prompt entry missing");
    }
    private static void grammar(String name,DecisionGrammar grammar,ActionDecision decision,boolean expected)throws Exception{
        Map<String,Object> c=new LinkedHashMap<String,Object>();c.put("name",name);c.put("grammar",grammar.text);
        JSONObject a=new JSONObject().put("reason",decision.reason).put("action",decision.action).put("observation_id",decision.observationId);
        if("notes.create".equals(decision.action))a.put("app_label",decision.appLabel).put("package",decision.packageName).put("text",decision.text);
        else{a.put("package",decision.packageName);if(decision.nodeId!=null)a.put("node_label",decision.nodeLabel).put("node_id",decision.nodeId);if("type".equals(decision.action))a.put("text",decision.text);}
        c.put("json",a.toString());c.put("accepted",expected);grammarCases.add(c);
    }
    private static void actualCycle()throws Exception{
        SameStateNoEffectGuard g=new SameStateNoEffectGuard();
        for(int step:new int[]{2,3,4,7}){
            JSONObject b=saved(String.format("step-%02d-before.json",step)),a=saved(String.format("step-%02d-after.json",step)),r=saved(String.format("step-%02d-action.json",step));
            ActionDecision d=action(r);check(b.getString("observation_id").equals(d.observationId),"actual action-before observation binding");
            check(!g.rejects(d,b.getString("package"),state(b)),"first actual step is not preemptively invented ineffective");
            g.observed(d,b.getString("package"),state(b),a.getString("package"),state(a),r.getBoolean("accepted"),r.getBoolean("dispatched"),r.getBoolean("stale"));
        }
        JSONObject body=saved("step-08-before.json"),title=saved("step-10-before.json");
        check(g.rejects(action(saved("step-08-action.json")),P,state(body)),"real S2 return retains body no-effect refusal");
        check(g.rejects(action(saved("step-10-action.json")),P,state(title)),"real S3 return retains category no-effect refusal");
        check(!g.rejects(action(saved("step-08-action.json")),"com.example.other",state(body)),"no foreign package carry");
        check(!new SameStateNoEffectGuard().rejects(action(saved("step-08-action.json")),P,state(body)),"no other task carry");
    }
    private static void actualOldEditor()throws Exception{
        String owner=saved("owner.json").getString("instruction");JSONObject beforeRaw=saved("step-01-before.json"),afterRaw=saved("step-01-after.json");
        Frame before=frame(beforeRaw),after=frame(afterRaw);TaskAuthorization auth=TaskAuthorization.parse(owner);
        TaskCompletionGate g=completion(TASK,owner,auth,before);NotesTaskPhaseGuard guard=new NotesTaskPhaseGuard(TASK,auth);
        check(g.contract.body.equals(BODY),"exact immutable contract");
        check(before.nodes.stream().anyMatch(n->n.text.contains("Hepta-v43r4")&&n.text.contains("Audio_")),"real preexisting note and attachment retained");
        Object built=prompt(owner,phone(beforeRaw),auth.bind(TASK),g,guard);DecisionGrammar gb=(DecisionGrammar)field(built,"grammar");
        NotesTaskPhaseGuard.Domain d=(NotesTaskPhaseGuard.Domain)field(built,"phaseDomain");ActionDecision oldType=action(saved("step-01-action.json"));
        check("create_required".equals(d.projection.phase)&&d.clickIds.isEmpty()&&d.editIds.isEmpty()&&d.submitIds.isEmpty(),"old note has no editable/click/submit domain");
        check(!gb.actions.contains("type")&&!gb.actions.contains("click")&&gb.actions.contains("notes.create"),"same restrictions in production grammar");
        check(((String)field(built,"text")).contains("Hepta-v43r4")&&((String)field(built,"text")).contains("Audio_"),"observed old facts are not hidden to force behavior");
        denied(()->d.requireCurrent(oldType),"recorded destructive type denied after parse");denied(()->guard.requireCurrent(oldType),"same type denied by dispatch gate");
        ActionDecision oldClick=ActionDecision.parse(new JSONObject().put("reason","host choice on the real old title").put("action","click")
                .put("observation_id",before.observationId).put("package",P).put("node_label","标题").put("node_id","n1").toString(),ActionDecision.FIXED_INTENT_ACTION_SCHEMA);
        denied(()->d.requireCurrent(oldClick),"old title click denied after parse");grammar("old-note-title-click",gb,oldClick,false);
        ActionDecision good=create(before,BODY),bad=create(before,BODY+"更改");d.requireCurrent(good);checks++;
        denied(()->d.requireCurrent(bad),"owner body mismatch denied after parse");denied(()->guard.requireCurrent(bad),"owner body mismatch denied before dispatch");
        grammar("old-note-type",gb,oldType,false);grammar("owner-exact-create",gb,good,true);grammar("different-create-body",gb,bad,false);
        g.action(1,TaskCompletionGateHostTest.id(1),oldType,true,true,false,before,after,null);
        check(NotesCompletionEvidence.editor(after,BODY,new NotesCompletionEvidence.Installed(P,10382,Collections.singletonMap("base",NotesCompletionEvidence.OBSERVED_BASE_APK_SHA256))).matched,"recorded overwritten body is actually visible");
        check(!g.notesPhase(after).launchProved&&!g.notesPhase(after).editorObserved&&!g.verified(after),"actual body does not manufacture new-entry proof");
        check("create_required".equals(guard.prepare(g,after).phase),"phase cannot advance from ordinary type/model reason");
        NotesTaskPhaseGuard.Domain replacement=bind(guard,guard.prepare(g,before));
        denied(()->d.requireCurrent(good),"repair retires original domain identity");replacement.requireCurrent(good);checks++;
        guard.retire();denied(()->replacement.requireCurrent(good),"retired task cannot use its old domain");
        NotesTaskPhaseGuard other=new NotesTaskPhaseGuard(TaskCompletionGateHostTest.id(999),auth);
        denied(()->other.publish(replacement),"other task cannot publish foreign domain");
        denied(()->other.prepare(g,before),"other task cannot borrow completion facts");
    }
    private static void stagesAndAuthority()throws Exception{
        String owner=TaskCompletionGateHostTest.OWNER;TaskAuthorization auth=TaskAuthorization.parse(owner);
        TaskCompletionGate g=TaskCompletionGateHostTest.gate();NotesTaskPhaseGuard guard=new NotesTaskPhaseGuard(TaskCompletionGateHostTest.TASK,auth);
        Frame before=TaskCompletionGateHostTest.initial();g.observed(before);
        NotesTaskPhaseGuard.Domain initial=bind(guard,guard.prepare(g,before));
        ActionDecision create=create(before,TaskCompletionGateHostTest.BODY);String run=TaskCompletionGateHostTest.id(123);
        Map<String,Object> receipt=fixed(TaskCompletionGateHostTest.TASK,before,create,run);
        Frame editor=TaskCompletionGateHostTest.editor();g.action(1,run,create,true,true,false,before,editor,receipt);
        NotesTaskPhaseGuard.Projection p=guard.prepare(g,editor);check("leave_created_editor".equals(p.phase),"real bound create/body permits leave stage");
        check(!p.fixedTargets(targets()).containsKey("notes.create")&&p.edits(set("n0")).isEmpty(),"no second create or unnecessary rewrite");
        check(!g.verified(editor)&&((String)p.evidence().get("next_goal")).contains("back 被接受不等于保存"),"leave hint is not save proof");
        Frame listing=TaskCompletionGateHostTest.listing();ActionDecision back=TaskCompletionGateHostTest.action(editor,"back",null,null);
        g.action(2,TaskCompletionGateHostTest.id(124),back,true,true,false,editor,listing,null);p=guard.prepare(g,listing);
        check("reopen_saved_item".equals(p.phase)&&p.clicks(set("n0","n9")).equals(set("n0")),"only actual unique list item survives intersection");
        check(p.clicks(set("n9")).isEmpty(),"phase never adds list item absent from supplied domain");
        Frame reopened=TaskCompletionGateHostTest.editor();g.action(3,TaskCompletionGateHostTest.id(125),TaskCompletionGateHostTest.action(listing,"click",null,"n0"),true,true,false,listing,reopened,null);
        check(g.verified(reopened)&&"verify_reopened_editor".equals(guard.prepare(g,reopened).phase),"existing complete evidence chain remains required");
        Frame foreign=new Frame(reopened.observationId,P,reopened.windowId,9,"11111111-1111-1111-1111-111111111111",1,true,false,reopened.nodes);
        check(guard.prepare(g,foreign).clicks(set("n0")).isEmpty(),"foreign display cannot inherit editor qualification");
        g.invalidateInstalled("host replacement");check(guard.prepare(g,reopened).clicks(set("n0")).isEmpty(),"installed identity invalidation narrows immediately");
        String unknown="只读当前页面，不要点击或输入。";TaskAuthorization readOnly=TaskAuthorization.parse(unknown);NotesTaskPhaseGuard un=new NotesTaskPhaseGuard(TASK,readOnly);
        NotesTaskPhaseGuard.Projection u=un.prepare(null,before);check(!un.supported()&&"unrestricted".equals(u.phase),"unknown contract acquires no Notes workflow");
        denied(()->u.bind(set("n0"),Collections.<String>emptySet(),Collections.<String>emptySet(),Collections.<String,FixedIntentTarget>emptyMap()),"phase cannot widen banned click");
        String denyCreate=TaskCompletionGateHostTest.owner("原文。禁止notes.create。样本");TaskAuthorization deniedAuth=TaskAuthorization.parse(denyCreate);
        check(!deniedAuth.allowedTools.contains("notes.create"),"explicit parser denial exists for adversarial literal clause");
        NotesTaskPhaseGuard deniedGuard=new NotesTaskPhaseGuard(TASK,deniedAuth);TaskCompletionGate deniedCompletion=completion(TASK,denyCreate,deniedAuth,before);
        check(deniedGuard.supported()&&deniedGuard.prepare(deniedCompletion,before).fixedTargets(targets()).isEmpty(),"recognized contract never grants denied create");
        check(initial.editIds.isEmpty(),"initial snapshot remains immutable after later stage updates");
    }
    private static void serviceRefusals()throws Exception{
        try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            TaskCompletionGateHostTest.installPackage(e,"notes.create");e.service.prepare(P);
            check(e.service.acquireTask(e.task,()->{}),"service task acquired");
            QualificationScopeConfig.Bound scope=QualificationScopeConfig.capture(e.service,e.task,null,e.runtime);e.service.bindQualificationScope(e.task,scope);
            TaskAuthorization auth=TaskAuthorization.parse(TaskCompletionGateHostTest.OWNER);TaskAuthorization.Gate gate=e.service.bindTaskAuthorization(e.task,auth);
            NotesTaskPhaseGuard phase=e.service.notesTaskPhaseFor(e.task,gate);
            HeptaAccessibilityService.ActionOutcome absent=e.run("type",P);check(!absent.accepted&&!absent.dispatched&&e.service.effects()==0&&absent.detail.contains("notes_task_phase"),"legacy perform overload cannot bypass missing supported phase");
            Method bridge=LocalTaskController.class.getDeclaredMethod("completionFrame",PhoneObservation.class);bridge.setAccessible(true);
            Frame observed=(Frame)bridge.invoke(null,e.service.current);TaskCompletionGate g=completion(e.task,TaskCompletionGateHostTest.OWNER,auth,observed);
            Object built=prompt(TaskCompletionGateHostTest.OWNER,e.service.current,gate,g,phase);check(built!=null,"actual prompt publishes service-owned phase");
            for(String tool:new String[]{"type","click"}){
                HeptaAccessibilityService.ActionOutcome refused=e.run(tool,P);check(!refused.accepted&&!refused.dispatched&&e.service.effects()==0&&refused.detail.contains("notes_task_phase"),"service blocks old editor "+tool);
            }
            ActionDecision wrong=create(observed,TaskCompletionGateHostTest.BODY+"different");
            ObservedTargetLabels labels=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,observed.observationId,P,Collections.singletonMap("n0",e.service.node.text));
            final HeptaAccessibilityService.ActionOutcome[] result=new HeptaAccessibilityService.ActionOutcome[1];
            e.service.perform(e.task,e.service.current,wrong,labels,targets().get("notes.create"),gate,TaskCompletionGateHostTest.id(222),()->false,value->result[0]=value);
            check(result[0]!=null&&!result[0].accepted&&!result[0].dispatched&&e.service.effects()==0&&result[0].detail.contains("notes_task_phase"),"actual service refuses different fixed payload before dispatch or ledger consumption");
            e.service.releaseTask(e.task);denied(()->phase.requireCurrent(e.action("type",P)),"released service task retires phase");
        }
    }
    private static void retiredBeforeWorkerEntry()throws Exception{
        try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            check(e.service.acquireTask(e.task,()->{}),"pre-worker task acquired");
            TaskAuthorization.Gate gate=e.service.bindTaskAuthorization(e.task,TaskAuthorization.parse(TaskCompletionGateHostTest.OWNER));
            final int[] ended={0};final LocalTaskController.TaskResult[] terminal={null};
            LocalInference model=new LocalInference(){
                public LocalRuntimeConfig configuration(){throw new AssertionError("retired lease cannot reach configuration");}
                public TaskCleanup endTask(){ended[0]++;return TaskCleanup.noWorker();}
                public Handle generate(String p,String s,File image,DecisionGrammar grammar,int tokens,long timeout,Callback callback){throw new AssertionError("retired lease cannot infer");}
            };
            LocalTaskController controller=new LocalTaskController(e.service,model);
            controller.setListener(new LocalTaskController.Listener(){public void onState(String value){}public void onFinished(LocalTaskController.TaskResult result){terminal[0]=result;}});
            // Explicit IO scheduling boundary: start() has already committed its
            // task fields, while its queued worker has not entered runTask yet.
            field(controller,"currentTaskId",e.task);field(controller,"running",Boolean.TRUE);
            HeptaAccessibilityService.live=null;
            Method run=LocalTaskController.class.getDeclaredMethod("runTask",String.class,String.class,String.class,TaskAuthorization.Gate.class,BackgroundSession.Selection.class);
            run.setAccessible(true);run.invoke(controller,e.task,TaskCompletionGateHostTest.OWNER,null,gate,null);
            check(ended[0]==1&&terminal[0]!=null&&!((Boolean)field(controller,"running")).booleanValue(),"service loss before worker entry still runs final cleanup and terminal callback");
            check(e.service.lease==null&&e.service.effects()==0,"early phase lookup failure releases lease without effects");
            controller.close();
        }
    }
    public static void main(String[] args)throws Exception{
        Path fixture=Paths.get(args[0]),out=Paths.get(args[1]);Files.createDirectories(out);
        QualificationScopeHostTest.output=out.resolve("service-io");Files.createDirectories(QualificationScopeHostTest.output);
        String raw=new String(Files.readAllBytes(fixture),StandardCharsets.UTF_8);check(FIXTURE_SHA.equals(ObservedImeEnter.hash(raw)),"frozen real v45 trace SHA");savedFiles=new JSONObject(raw).getJSONObject("files");
        actualCycle();actualOldEditor();stagesAndAuthority();serviceRefusals();retiredBeforeWorkerEntry();
        Files.write(out.resolve("grammar-cases.json"),new JSONArray(grammarCases).toString().getBytes(StandardCharsets.UTF_8));
        System.out.println("PASS "+checks+" notes task phase and recorded two-state contracts; android_runtime=false; phone_tested=false");
    }
}
